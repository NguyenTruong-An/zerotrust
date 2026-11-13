"""Read-only preparation of one exact local Risk promotion. No cutover executor.

plan/validate never create files, containers, volumes, images or checkpoints.
Reserved mutation commands fail closed, even if a document says APPROVED.
"""
import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PROJECT = 'zt-full-function-20261111b'
PREFIX = 'target/full-function-20261111b/'
OLD = 'sha256:3f540f3de29a4ac69ec916a81d153b8d4befd9238c9c06b26b9b9f0f2b843571'
NEW = 'sha256:1ec3c4db626d6c232ca9a30c61188d69e883d40eb0005c29bd0d15921258686a'
SOURCE = 'risk-scoring-service/src/main/java/com/zerotrust/risk/repository/DeviceTrustStateRepository.java'
SOURCE_HASH = '779cd1e507f1aa139e57dd8ed42422e7afebee95df3666abc2c18ceb19afdfe8'
BUILD_HEAD = '81d6322a7624d3632f69215daf45537f922dd950'
ACTIVE_MARKER = PREFIX+'private/risk-promotion.active.json'
DEFAULT_MANIFEST = HERE/'risk-promotion.v1.json'
HEALTHY = {'mysql','redis','crl','keycloak','risk','backend','frontend','gateway','ingress'}
PROPERTIES = 'risk.policy.'
GEO = {
    PROPERTIES+'network-risk.geoip.enabled': True,
    PROPERTIES+'network-risk.geoip.city-database-path': '/geoip/GeoLite2-City.mmdb',
    PROPERTIES+'network-risk.geoip.asn-database-path': '/geoip/GeoLite2-ASN.mmdb',
}


class Rejected(RuntimeError):
    pass


def need(ok, code):
    if not ok:
        raise Rejected(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sha_file(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
    return digest.hexdigest()


def unique_pairs(pairs):
    result={}
    for key,value in pairs:
        need(key not in result,'DUPLICATE_JSON_KEY')
        result[key]=value
    return result


def json_bytes(raw):
    try:
        return json.loads(raw,object_pairs_hook=unique_pairs)
    except (ValueError,UnicodeError):
        raise Rejected('INVALID_JSON') from None


def local_path(root, relative):
    need(type(relative) is str and '\\' not in relative,'INVALID_RELATIVE_PATH')
    p=Path(relative)
    need(not p.is_absolute() and ':' not in relative and '..' not in p.parts,'PATH_ESCAPE')
    target=root/p
    need(target.resolve().is_relative_to(root.resolve()),'PATH_ESCAPE')
    # Reject links/junctions in every existing ancestor, including Windows reparse points.
    for part in [target,*target.parents]:
        if part==root:break
        need(not part.is_symlink() and not (hasattr(part,'is_junction') and part.is_junction()),'LINKED_PATH_REJECTED')
    return target


def schema_validate(value, schema, path='manifest', root_schema=None):
    """Small strict validator for the keywords used in our checked-in schema."""
    root_schema=root_schema or schema
    if '$ref' in schema:
        ref=schema['$ref'];need(ref.startswith('#/$defs/') and ref.count('/')==2,'SCHEMA_REF')
        return schema_validate(value,root_schema['$defs'][ref.rsplit('/',1)[1]],path,root_schema)
    types={'object':dict,'array':list,'string':str,'integer':int,'boolean':bool,'null':type(None)}
    if 'type' in schema:
        allowed=schema['type'] if isinstance(schema['type'],list) else [schema['type']]
        need(any(type(value) is types[t] for t in allowed),'SCHEMA_TYPE:'+path)
    if 'const' in schema:need(value==schema['const'],'SCHEMA_CONST:'+path)
    if 'enum' in schema:need(value in schema['enum'],'SCHEMA_ENUM:'+path)
    if type(value) is dict:
        props=schema.get('properties',{})
        need(set(schema.get('required',[]))<=set(value),'SCHEMA_REQUIRED:'+path)
        if schema.get('additionalProperties') is False:need(set(value)<=set(props),'SCHEMA_EXTRA_FIELD:'+path)
        for k,v in value.items():
            child=props.get(k,schema.get('additionalProperties'))
            if isinstance(child,dict):schema_validate(v,child,path+'.'+k,root_schema)
    elif type(value) is list:
        if 'minItems' in schema:need(len(value)>=schema['minItems'],'SCHEMA_MIN_ITEMS:'+path)
        if schema.get('uniqueItems'):need(len({json.dumps(v,sort_keys=True) for v in value})==len(value),'SCHEMA_DUPLICATE_ITEM:'+path)
        for v in value:schema_validate(v,schema.get('items',{}),path+'[]',root_schema)
    elif type(value) is str:
        if 'pattern' in schema:need(re.fullmatch(schema['pattern'],value) is not None,'SCHEMA_PATTERN:'+path)
    elif type(value) is int:
        if 'minimum' in schema:need(value>=schema['minimum'],'SCHEMA_MIN:'+path)


def properties(raw):
    result={}
    for line in raw.decode('utf-8-sig').splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            k,v=line.split('=',1);result[k.strip()]=v.strip()
    return result


def effective_policy(defaults, overrides, env):
    result=properties(defaults);result.update(properties(overrides))
    def resolve(m):
        key,sep,fallback=m[1].partition(':')
        return env[key] if key in env else fallback if sep else '<UNSET>'
    result={k:re.sub(r'\$\{([^}]+)\}',resolve,v) for k,v in result.items() if k.startswith(PROPERTIES)}
    prefix=PROPERTIES+'network-risk.'
    return {'model':result.get(PROPERTIES+'model'),
        'weights':{k:result.get(PROPERTIES+'weights.'+k) for k in ('device','network','temporal','authentication-history')},
        'thresholds':{k:result.get(PROPERTIES+'thresholds.'+k) for k in ('medium-minimum','high-minimum')},
        'network_enabled':result.get(prefix+'enabled'),
        'scores':{k:result.get(prefix+k+'-score') for k in ('default','elevated','high')},
        'lists':{k:[v.strip() for v in result.get(prefix+k,'').split(',') if v.strip()] for k in
            ('trusted-cidrs','elevated-risk-cidrs','high-risk-cidrs','trusted-country-codes','elevated-risk-country-codes','high-risk-country-codes')},
        'geoip_enabled':result.get(prefix+'geoip.enabled')}


def container_witness(row):
    """Full non-secret execution contract; ignores changing health timestamps/IP leases."""
    cfg=row['Config'];host=row['HostConfig']
    return {'id':row['Id'],'image':row['Image'],
        'mounts':sorted([{k:m.get(k) for k in ('Type','Name','Source','Destination','RW')} for m in row['Mounts']],key=lambda m:m['Destination']),
        'networks':sorted(row['NetworkSettings']['Networks']),
        'ports':host.get('PortBindings') or {},'user':cfg.get('User'),
        'entrypoint':cfg.get('Entrypoint'),'cmd':cfg.get('Cmd'),
        'environment_sha256':sha(json.dumps(sorted(cfg.get('Env') or [])).encode()),
        'readonly_rootfs':host.get('ReadonlyRootfs',False),'privileged':host.get('Privileged',False),
        'cap_add':host.get('CapAdd'),'cap_drop':host.get('CapDrop'),'security_opt':host.get('SecurityOpt'),
        'restart':host.get('RestartPolicy'),'memory':host.get('Memory'),'tmpfs':host.get('Tmpfs'),
        'binds':host.get('Binds'),'devices':host.get('Devices'),'network_mode':host.get('NetworkMode')}


def network_witness(row):
    return {k:row[k] for k in ('Id','Name','Driver','Internal','IPAM','Labels')}


def risk_writers(rows, include_stopped=False):
    core=PROJECT+'_core'
    return [r for r in rows if (r['State']['Running'] or include_stopped) and core in r['NetworkSettings']['Networks']
        and ('risk' in (r['NetworkSettings']['Networks'][core].get('Aliases') or [])
            or (r['Config'].get('Labels') or {}).get('com.docker.compose.service')=='risk'
            or r['Image'] in (OLD,NEW)
            or any(m.get('Name')==PROJECT+'_risk-config' for m in r['Mounts']))]


DIFF_PREFIX=('git','--no-pager','-c','core.fsmonitor=false','diff','--no-ext-diff','--no-textconv','--name-only')
DIFF_PATHS=('--','risk-scoring-service/src','risk-scoring-service/pom.xml','deploy/docker/Dockerfile.java','.dockerignore')


def readonly_diff_args(old,new):
    need(all(type(x) is str and re.fullmatch('[0-9a-f]{40}',x) for x in (old,new)),'GIT_REVISION_NOT_EXACT_COMMIT')
    return (*DIFF_PREFIX,old,new,*DIFF_PATHS)


def is_readonly_diff(args):
    n=len(DIFF_PREFIX)
    return (len(args)==n+2+len(DIFF_PATHS) and args[:n]==DIFF_PREFIX and args[n+2:]==DIFF_PATHS
            and all(re.fullmatch('[0-9a-f]{40}',x) for x in args[n:n+2]))


class ReadOnlyDocker:
    """Only inspect, cp-to-stdout and one fixed SELECT; never shell interpolation."""
    def command(self,*args):
        allowed=(args in (('docker','context','show'),('docker','info','--format','{{.OSType}}'),
            ('docker','ps','-aq'),('git','rev-parse','HEAD'))
            or args[:3]==('docker','context','inspect')
            or args[:3]==('docker','image','inspect')
            or args[:3]==('docker','network','inspect')
            or args[:2]==('docker','inspect')
            or is_readonly_diff(args)
            or args[:2]==('docker','cp') and len(args)==4 and args[-1]=='-'
                and args[2] in tuple(PROJECT+'-risk-1:/run/demo/'+f for f in ('application.properties','jvm.args','ca.crt','server.crt'))+(PROJECT+'-crl-1:/run/demo/ca.crl',)
            or args==('docker','exec',PROJECT+'-mysql-1','mysql','--defaults-extra-file=/fixture/root.cnf',
                '--batch','--skip-column-names','-e',"SELECT checksum,success FROM pd_staging_risk.flyway_schema_history WHERE version='5'"))
        need(allowed,'READ_ONLY_ADAPTER_COMMAND_FORBIDDEN')
        try:
            p=subprocess.run(args,capture_output=True,timeout=45,cwd=ROOT)
        except (OSError,subprocess.TimeoutExpired):raise Rejected('READ_ONLY_COMMAND_UNAVAILABLE') from None
        need(p.returncode==0,'READ_ONLY_COMMAND_FAILED')
        return p.stdout

    def local(self):
        need(not os.environ.get('DOCKER_HOST') and not os.environ.get('DOCKER_CONTEXT'),'REMOTE_DOCKER_REJECTED')
        context=self.command('docker','context','show').decode().strip()
        endpoint=self.command('docker','context','inspect','--format','{{.Endpoints.docker.Host}}',context).decode().strip()
        need(endpoint.startswith(('npipe:','unix:')),'REMOTE_DOCKER_REJECTED')
        need(self.command('docker','info','--format','{{.OSType}}').decode().strip()=='linux','DOCKER_PLATFORM')

    def containers(self):
        ids=self.command('docker','ps','-aq').decode().split()
        return json_bytes(self.command('docker','inspect',*ids)) if ids else []

    def image(self,ident):
        return json_bytes(self.command('docker','image','inspect',ident))[0]

    def networks(self,names):
        return json_bytes(self.command('docker','network','inspect',*names))

    def read_config(self,name,file):
        need(name==PROJECT+'-risk-1' and file in ('application.properties','jvm.args','ca.crt','server.crt')
             or name==PROJECT+'-crl-1' and file=='ca.crl','READ_CONFIG_SCOPE')
        raw=self.command('docker','cp',name+':/run/demo/'+file,'-')
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            files=[m for m in archive.getmembers() if m.isfile()]
            need(len(files)==1 and files[0].size<1024*1024,'CONFIG_ARCHIVE_LAYOUT')
            return archive.extractfile(files[0]).read()

    def v5(self):
        return self.command('docker','exec',PROJECT+'-mysql-1','mysql','--defaults-extra-file=/fixture/root.cnf',
            '--batch','--skip-column-names','-e',"SELECT checksum,success FROM pd_staging_risk.flyway_schema_history WHERE version='5'").decode().strip()

    def head(self):return self.command('git','rev-parse','HEAD').decode().strip()

    def build_input_changes(self,old,new):
        return self.command(*readonly_diff_args(old,new)).decode().splitlines()


def tls_validate(ca_bytes,leaf_bytes,crl_bytes,now):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import padding
    ca=x509.load_pem_x509_certificate(ca_bytes);leaf=x509.load_pem_x509_certificate(leaf_bytes)
    crl=x509.load_pem_x509_crl(crl_bytes)
    for cert in (ca,leaf):need(cert.not_valid_before_utc<=now<cert.not_valid_after_utc,'TLS_CERT_EXPIRED')
    need(crl.last_update_utc<=now<crl.next_update_utc,'TLS_CRL_EXPIRED')
    need(leaf.issuer==ca.subject and crl.issuer==ca.subject,'TLS_ISSUER_MISMATCH')
    try:
        leaf.verify_directly_issued_by(ca)
        ca.public_key().verify(crl.signature,crl.tbs_certlist_bytes,padding.PKCS1v15(),crl.signature_hash_algorithm)
    except Exception:raise Rejected('TLS_SIGNATURE_INVALID') from None
    need('risk' in leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName),'TLS_SAN')
    need(crl.get_revoked_certificate_by_serial_number(leaf.serial_number) is None,'TLS_REVOKED')


def assert_legacy_runtime(root=ROOT, adapter=None):
    """Legacy operations may never overwrite an installed promotion. Fail before Compose."""
    need(not local_path(root,ACTIVE_MARKER).exists(),'PROMOTED_PROFILE_USE_REVIEWED_CONTROLLER')
    need(not local_path(root,PREFIX+'promotion-private').exists(),'ACTIVE_CONTEXT_OWNS_OPERATIONS_USE_REVIEWED_CONTROLLER')
    adapter=adapter or ReadOnlyDocker();adapter.local()
    all_rows=adapter.containers();rows=[r for r in all_rows if r['Name']=='/'+PROJECT+'-risk-1']
    canonical_ids={r['Id'] for r in rows}
    need(all(x['Id'] in canonical_ids for x in risk_writers(all_rows,include_stopped=True)),
         'CONFLICTING_RISK_WRITERS_OR_RECOVERY_REQUIRED')
    writers=risk_writers(all_rows)
    need(not writers or len(rows)==1 and len(writers)==1 and writers[0]['Id']==rows[0]['Id'],'CONFLICTING_RISK_WRITERS')
    if not rows:return # unchanged initial-install path; normal ownership checks still apply
    need(len(rows)==1,'CONFLICTING_RISK_WRITERS')
    x=rows[0]
    need(x['Image']==OLD,'PROMOTED_OR_UNKNOWN_RISK_LEGACY_OPERATION_BLOCKED')
    need(len(x['Mounts'])==1 and x['Mounts'][0].get('Name')==PROJECT+'_risk-config'
         and x['Mounts'][0]['Destination']=='/run/demo' and not x['Mounts'][0]['RW'],'CHANGED_RISK_MOUNTS_LEGACY_OPERATION_BLOCKED')
    env=dict(v.split('=',1) for v in x['Config'].get('Env',[]))
    need('SPRING_APPLICATION_JSON' not in env and not any(k.startswith(('RISK_GEOIP_','RISK_NETWORK_','RISK_POLICY_')) for k in env),'CHANGED_RISK_CONFIG_LEGACY_OPERATION_BLOCKED')


def inspect_manifest(manifest, root=ROOT, adapter=None, now=None, schema=None, check_tls=tls_validate):
    schema=schema or json_bytes((HERE/'risk-promotion.schema.json').read_bytes())
    schema_validate(manifest,schema)
    adapter=adapter or ReadOnlyDocker();now=now or dt.datetime.now(dt.timezone.utc)
    need(manifest['project']==PROJECT,'WRONG_PROJECT')
    need(manifest['images']=={'old':OLD,'proposed':NEW},'UNEXPECTED_IMAGE_IDENTITY')
    need(not local_path(root,ACTIVE_MARKER).exists(),'ALREADY_PROMOTED_OR_RECOVERY_REQUIRED')
    adapter.local()
    for entry in manifest['receipts']:
        path=local_path(root,entry['path']);need(path.is_file(),'MISSING_BASE_RECEIPT')
        need(sha_file(path)==entry['sha256'],'BASE_RECEIPT_DRIFT')
    source=manifest['source']
    need(source['path']==SOURCE and source['sha256']==SOURCE_HASH,'SOURCE_IDENTITY')
    need(source['build_HEAD']==BUILD_HEAD and re.fullmatch('[0-9a-f]{40}',source['review_HEAD']) is not None,'SOURCE_COMMIT_IDENTITY')
    need(source['build_receipt']==PREFIX+'phase2/locking-candidate-image.json' and source['signed_provenance']=='NOT_VERIFIED','PROVENANCE_REFERENCE')
    build=json_bytes(local_path(root,source['build_receipt']).read_bytes())
    need(build['id']==NEW and build['source_HEAD']==BUILD_HEAD and build['dirty_source_file_sha256']==SOURCE_HASH
         and build['purpose']=='ISOLATED_TEST_ONLY_NOT_RELEASE_PROMOTION','BUILD_RECEIPT_CONTENT')
    need(sha_file(local_path(root,SOURCE))==SOURCE_HASH,'SOURCE_DRIFT')
    need(adapter.head()==source['review_HEAD'],'HEAD_DRIFT_REVIEW_REQUIRED')
    need(not adapter.build_input_changes(source['build_HEAD'],source['review_HEAD']),'COMMITTED_BUILD_INPUT_DRIFT')
    for ident in (OLD,NEW):
        image=adapter.image(ident)
        need(image['Id']==ident,'IMAGE_MISMATCH')
        need(image['Os']=='linux' and image['Architecture']=='amd64','IMAGE_PLATFORM')
    rows=adapter.containers();owned=[]
    for r in rows:
        labels=r['Config'].get('Labels') or {}
        if labels.get('com.docker.compose.project')==PROJECT:
            need(labels.get('io.zerotrust.scope')==PROJECT,'OWNERSHIP_MISMATCH')
            owned.append(r)
    services={r['Config']['Labels']['com.docker.compose.service']:r for r in owned}
    need(HEALTHY<=set(services),'MISSING_OWNED_SERVICE')
    need(all(services[s]['State']['Running'] and services[s]['State'].get('Health',{}).get('Status')=='healthy' for s in HEALTHY),'ACTIVE_STACK_NOT_HEALTHY')
    witnesses={s:container_witness(services[s]) for s in HEALTHY}
    need(witnesses==manifest['baseline_runtime'],'RUNTIME_CONFIG_NETWORK_PORT_OR_MOUNT_DRIFT')
    names=sorted({n for r in owned for n in r['NetworkSettings']['Networks']})
    networks={x['Name']:network_witness(x) for x in adapter.networks(names)}
    need(networks==manifest['networks'],'NETWORK_DEFINITION_DRIFT')
    need(networks[PROJECT+'_core']['Internal'] and networks[PROJECT+'_recovery']['Internal'],'PRIVATE_NETWORK_REQUIRED')
    need(all(x['Labels'].get('com.docker.compose.project')==PROJECT for x in networks.values()),'NETWORK_OWNERSHIP')
    core=PROJECT+'_core'
    writers=risk_writers(rows)
    need(len(writers)==1 and writers[0]['Id']==services['risk']['Id'],'CONFLICTING_RISK_WRITERS')
    need(services['risk']['Image']==OLD,'UNEXPECTED_ACTIVE_RISK_IMAGE')
    for r in owned:
        for m in r['Mounts']:
            need(m['Type']=='volume' and m.get('Name','').startswith(PROJECT+'_'),'UNSAFE_BASE_MOUNT')
        if r['Config']['Labels']['com.docker.compose.service'] not in ('ingress','crl'):
            need(not r['HostConfig'].get('PortBindings'),'UNEXPECTED_PUBLIC_PORT')
    for s,port in (('ingress','39443'),('crl','39445')):
        need(services[s]['HostConfig']['PortBindings']=={port+'/tcp':[{'HostIp':'127.0.0.1','HostPort':port}]},'UNSAFE_LISTENER')
    app=adapter.read_config(PROJECT+'-risk-1','application.properties')
    jvm=adapter.read_config(PROJECT+'-risk-1','jvm.args')
    need(sha(app)==manifest['config']['application_sha256'] and sha(jvm)==manifest['config']['jvm_sha256'],'ACTIVE_CONFIG_DRIFT')
    need(b'-Dcom.sun.net.ssl.checkRevocation=true' in jvm and b'-Dcom.sun.security.enableCRLDP=true' in jvm,'TLS_REVOCATION_REQUIRED')
    props=properties(app)
    need(props.get('server.ssl.enabled')=='true' and 'sslMode=VERIFY_IDENTITY' in props.get('spring.datasource.url',''),'TLS_VERIFICATION_REQUIRED')
    defaults=local_path(root,manifest['config']['artifact_defaults']['path'])
    need(sha_file(defaults)==manifest['config']['artifact_defaults']['sha256'],'ARTIFACT_DEFAULTS_DRIFT')
    env=dict(v.split('=',1) for v in services['risk']['Config'].get('Env',[]))
    need('SPRING_APPLICATION_JSON' not in env,'UNEXPECTED_ACTIVE_OVERRIDE')
    policy=effective_policy(defaults.read_bytes(),app,env)
    need(policy==manifest['policy'],'B0_OR_NETWORK_POLICY_DRIFT')
    need(policy['weights']==dict.fromkeys(('device','network','temporal','authentication-history'),'0.25')
        and policy['thresholds']=={'medium-minimum':'40','high-minimum':'75'} and policy['model']=='BASELINE_B0','INCOMPATIBLE_B0')
    need(policy['network_enabled']=='true' and policy['geoip_enabled']=='false'
        and policy['scores']=={'default':'50','elevated':'50','high':'100'},'NETWORK_POLICY')
    need(all(not v for k,v in policy['lists'].items() if k.endswith('country-codes')),'UNAPPROVED_COUNTRY_POLICY')
    need(adapter.v5()=='661092940\t1','INCOMPATIBLE_V5_LEDGER')
    need(manifest['override']['application']==GEO,'UNAPPROVED_APPLICATION_OVERRIDE')
    need(manifest['override']['mount']=={'source':manifest['geoip']['directory'],'target':'/geoip','read_only':True},'UNSAFE_PROPOSED_MOUNT')
    need(manifest['override']['security']=={'user':'10001:10001','read_only':True,'cap_drop':['ALL'],
        'security_opt':['no-new-privileges'],'tmpfs':['/tmp:mode=1777'],'memory_mib':640},'UNAPPROVED_SECURITY_OVERRIDE')
    geo=manifest['geoip'];directory=local_path(root,geo['directory'])
    need(geo['directory']==PREFIX+'geoip-private/data/releases/'+geo['release'],'UNSAFE_GEOIP_DIRECTORY')
    acquisition=json_bytes(local_path(root,geo['acquisition_receipt']).read_bytes())
    need(acquisition['release']==geo['release'],'DATASET_RELEASE_DRIFT')
    for edition in ('GeoLite2-City','GeoLite2-ASN'):
        record=geo['files'][edition];path=local_path(root,geo['directory']+'/'+edition+'.mmdb')
        need(path.is_file(),'MISSING_GEOIP_DATASET')
        need(path.stat().st_size==record['bytes'] and sha_file(path)==record['sha256'],'CORRUPT_GEOIP_DATASET')
        need(record['sha256']==acquisition['files'][edition]['mmdb_sha256'],'DATASET_RECEIPT_MISMATCH')
        meta=record['metadata'];expected=acquisition['metadata']['city' if edition.endswith('City') else 'asn']
        need(meta==expected and meta['database_type']==edition and meta['binary_format']==2,'GEOIP_METADATA')
        built=dt.datetime.fromisoformat(meta['build_at'].replace('Z','+00:00'))
        need(now-dt.timedelta(days=30)<=built<=now+dt.timedelta(days=1),'STALE_OR_FUTURE_GEOIP')
    tls=manifest['tls']
    for entry in tls.values():need(sha_file(local_path(root,entry['path']))==entry['sha256'],'TLS_MATERIAL_DRIFT')
    need(sha(adapter.read_config(PROJECT+'-risk-1','ca.crt'))==tls['ca']['sha256']
         and sha(adapter.read_config(PROJECT+'-risk-1','server.crt'))==tls['leaf']['sha256'],'ACTIVE_TLS_MATERIAL_DRIFT')
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    actual_crl=x509.load_der_x509_crl(adapter.read_config(PROJECT+'-crl-1','ca.crl')).public_bytes(Encoding.PEM)
    need(sha(actual_crl)==tls['crl']['sha256'],'ACTIVE_CRL_DRIFT')
    check_tls(*[local_path(root,tls[k]['path']).read_bytes() for k in ('ca','leaf','crl')],now)
    rollback=manifest['rollback']
    need(rollback['image']==OLD and rollback['runtime']==manifest['baseline_runtime']['risk']
        and rollback['application_sha256']==manifest['config']['application_sha256']
        and rollback['jvm_sha256']==manifest['config']['jvm_sha256'] and rollback['restore_database'] is False,'UNVERIFIED_ROLLBACK_DESTINATION')
    need(manifest['checkpoint']['root']==PREFIX+'promotion-private/checkpoints'
        and manifest['checkpoint']['status']=='NOT_CREATED','CHECKPOINT_REVIEW_REQUIRED')
    need(manifest['execution_enabled'] is False and manifest['approval_status']=='PENDING','UNAPPROVED_EXECUTION_STATE')
    return {'status':'PASS','project':PROJECT,'active_image':OLD,'proposed_image':NEW,
        'checks':'schema/provenance/receipts/ownership/images/config/B0/V5/TLS-CRL/data-integrity/network/mounts/writers/rollback',
        'geoip_verification':'reuse acquisition/metadata/lookup evidence; read-only SHA256 drift guard, no new DB lookup',
        'active_runtime_modified':False,'checkpoint':'NOT_CREATED','cutover_authorized':False,'D17':'PENDING','G8':'INTERNET_NO_GO'}


def future_design(manifest):
    """Declarative reviewed order only. Never passed to subprocess/shell/Compose."""
    return {
        'execution_enabled':False,'requires_separate_owner_authorization':True,
        'backup-only':{'ready':'DESIGN_ONLY','root':manifest['checkpoint']['root'],
            'steps':['acquire exclusive project operation lock and revalidate ownership',
                'maintenance: pause only owned School/Keycloak/Risk writers and stop owned Redis',
                'consistent dump of School/Keycloak/Risk with fixed defaults-extra-file; no import',
                'stream stopped Redis AOF archive and owned config into AES-256-GCM checkpoint',
                'store encryption key separately under private ACL; validate archive/MAC/checkpoint manifest',
                'finally resume only previously running owned services and verify health'],
            'state_invariants':['no database reset/recreation','no plaintext checkpoint','no secret output']},
        'apply':{'ready':'DISABLED','from':OLD,'to':NEW,'checkpoint_required':'fresh verified owned encrypted checkpoint',
            'steps':['explicit approval binds manifest SHA256/project/from/to/config/dataset/maintenance window',
                'exclusive lock; preflight plus baseline receipts; quiesce new auth/writers',
                'stop old Risk, create only new owned Risk with approved readonly dataset/security override',
                'never run two Risk aliases; health+GeoIP+targeted browser smoke before resume',
                'write separate promotion active marker/receipt atomically only after verified cutover',
                'on uncertainty retain maintenance and recover explicitly; never rerun install/materialize']},
        'rollback':{'ready':'DESIGN_ONLY','image':manifest['rollback']['image'],'restore_database':False,
            'preserve_current':['MFA generations','revoked trusted devices','pending operations','audit','user credentials'],
            'steps':['explicit owner approval; verify exact recorded old image/config/ownership and exclusive lock',
                'stop only promoted Risk; load recorded old config/image using current volumes',
                'verify TLS/health/V5/current security-state continuity before resuming local traffic',
                'record rollback separately; never restore DB/Redis snapshot or clear pending/generation']}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',nargs='?',default='plan',choices=('plan','validate','backup-only','restore-verify','apply','rollback','status','restart','stop','recover'))
    parser.add_argument('--manifest',type=Path,default=DEFAULT_MANIFEST)
    parser.add_argument('--execution-manifest',type=Path)
    parser.add_argument('--request',type=Path)
    args=parser.parse_args()
    if args.execution_manifest is not None:
        from promotion_executor import dispatch
        print(json.dumps(dispatch(args.action,args.execution_manifest,args.request),indent=2));return
    need(args.request is None,'REQUEST_REQUIRES_SCOPED_EXECUTION_MANIFEST')
    need(args.action in ('plan','validate'),'MUTATION_EXECUTOR_DISABLED_SEPARATE_AUTHORIZATION_AND_IMPLEMENTATION_REQUIRED')
    need(args.manifest.resolve().is_relative_to(ROOT.resolve()),'MANIFEST_OUTSIDE_CANONICAL')
    need(args.manifest.stat().st_size<=2*1024*1024,'MANIFEST_SIZE_LIMIT')
    manifest=json_bytes(args.manifest.read_bytes())
    result=inspect_manifest(manifest)
    if args.action=='plan':result['future_design']=future_design(manifest)
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    import sys
    sys.modules.setdefault('risk_promotion',sys.modules[__name__])
    try:main()
    except Exception as exc:
        code=str(exc) if type(exc) is Rejected else type(exc).__name__
        print(json.dumps({'status':'REJECTED','code':code,'active_runtime_modified':False}));raise SystemExit(1)
