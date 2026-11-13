"""Run only existing JWT negative tests against exact deployed application bytes.

The ordinary local target/classes differs from the deployed build. This harness
does not compile application code or rebuild images; it extracts deployed public
application classes and compiles only the selected existing test/fixture sources.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET
import zipfile

import operate as full

NS='http://maven.apache.org/POM/4.0.0'
ET.register_namespace('',NS)
Q=lambda s:'{'+NS+'}'+s


def child(parent,name,text=None):
    node=parent.find(Q(name))
    if node is None:node=ET.SubElement(parent,Q(name))
    if text is not None:node.text=str(text)
    return node


def fingerprint(folder):
    return {p.relative_to(folder).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.rglob('*.class')}


def main():
    mfa=sys.argv[1:]==['--mfa-orchestration']
    base=full.OUT/'phase2'/('artifact-mfa' if mfa else 'artifact-jwt');base.mkdir(exist_ok=True)
    jdks=list((full.ROOT/'target/pd-02-02/toolchain/jdk').glob('*/bin/javac.exe'))
    full.check(len(jdks)==1,'Pinned Java17 toolchain required')
    env=dict(os.environ);env['JAVA_HOME']=str(jdks[0].parent.parent);env['PATH']=str(jdks[0].parent)+os.pathsep+env['PATH']
    definitions={'backend':(full.ROOT,'PortalJwtDecoderTest',('PortalJwtDecoderTest',)),
                 'risk':(full.ROOT/'risk-scoring-service','RiskApiSecurityTests',('RiskApiSecurityTests',)),
                 'gateway':(full.ROOT/'gateway','GatewaySecurityTests',('GatewaySecurityTests','GatewayMockUpstream'))}
    if mfa:definitions={'backend':(full.ROOT,'UserServiceImplTest,KeycloakUserClientTest,RiskDeviceAdminClientTest',('UserServiceImplTest','KeycloakUserClientTest','RiskDeviceAdminClientTest'))}
    results={}
    for name,(module,suite,includes) in definitions.items():
        work=base/name;work.mkdir(exist_ok=True);classes=work/'runtime-classes';classes.mkdir(exist_ok=True)
        raw=subprocess.run(['docker','cp',full.PROJECT+'-'+name+'-1:/app/application.jar','-'],capture_output=True,check=True).stdout
        with tarfile.open(fileobj=io.BytesIO(raw)) as t:jar=t.extractfile(t.getmembers()[0]).read()
        with zipfile.ZipFile(io.BytesIO(jar)) as z:
            for path in z.namelist():
                if path.startswith('BOOT-INF/classes/') and not path.endswith('/'):
                    rel=Path(path.removeprefix('BOOT-INF/classes/'))
                    full.check(not rel.is_absolute() and '..' not in rel.parts,'Unsafe application resource path')
                    target=classes/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.read(path))
        before=fingerprint(classes)
        tree=ET.parse(module/'pom.xml');root=tree.getroot();build=child(root,'build')
        child(build,'directory',work/'target');child(build,'sourceDirectory',work/'empty')
        child(build,'outputDirectory',classes);child(build,'testSourceDirectory',module/'src/test/java')
        child(build,'testOutputDirectory',work/'test-classes')
        for kind,path in (('resources',work/'empty'),('testResources',module/'src/test/resources')):
            node=child(build,kind);node.clear();item=ET.SubElement(node,Q('resource' if kind=='resources' else 'testResource'));child(item,'directory',path)
        plugins=child(build,'plugins')
        def plugin(artifact):
            for p in plugins:
                if p.findtext(Q('artifactId'))==artifact:return p
            p=ET.SubElement(plugins,Q('plugin'));child(p,'groupId','org.apache.maven.plugins');child(p,'artifactId',artifact);return p
        compiler=child(plugin('maven-compiler-plugin'),'configuration');child(compiler,'skipMain','true')
        items=child(compiler,'testIncludes');items.clear()
        for include in includes:ET.SubElement(items,Q('testInclude')).text='**/'+include+'.java'
        sf=child(plugin('maven-surefire-plugin'),'configuration');child(sf,'useFile','false');child(sf,'disableXmlReport','true')
        pom=work/'pom.xml';tree.write(pom,encoding='utf-8',xml_declaration=True)
        p=subprocess.run([str(full.ROOT/'mvnw.cmd'),'--batch-mode','--no-transfer-progress','-f',str(pom),'-Dtest='+suite,'-Dmaven.main.skip=true','test'],
                         env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=300,cwd=full.ROOT)
        summaries=re.findall(r'Tests run: (\d+), Failures: (\d+), Errors: (\d+), Skipped: (\d+)',p.stdout+p.stderr)
        unchanged=before==fingerprint(classes)
        totals=list(map(int,summaries[-1])) if summaries else None
        results[name]={'suite':suite,'runtime_jar_sha256':hashlib.sha256(jar).hexdigest(),'runtime_class_count':len(before),
            'deployed_class_bytes_unchanged':unchanged,'tests_failures_errors_skipped':totals,'exit_code':p.returncode,
            'application_recompiled':False,'image_rebuilt':False,'status':'PASS' if p.returncode==0 and unchanged and totals and totals[0]>0 and totals[1:]==[0,0,0] else 'FAIL'}
        (base/'results.json').write_text(json.dumps(results,indent=2)+'\n')
        print(results[name]['status']+' exact deployed '+name+' JWT suite '+str(totals),flush=True)
        if results[name]['status']!='PASS':
            # No Maven payload/fixture-token/secret output is written to the receipt.
            safe=[re.sub(r'\x1b\[[0-9;]*m','',x) for x in (p.stdout+p.stderr).splitlines() if '[ERROR]' in x and 'JWT' not in x and 'token' not in x.lower()]
            (base/'failure-categories.json').write_text(json.dumps({'module':name,'error_categories':[x[:180] for x in safe[:8]]},indent=2)+'\n')
            raise SystemExit(1)


if __name__=='__main__':main()
