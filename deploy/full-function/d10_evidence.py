"""Seal only PASS offline D10 evidence; read-only Docker/active SQL, local report writes."""
import datetime,hashlib,json,re,subprocess,xml.etree.ElementTree as ET
from pathlib import Path
import d10_isolated as fixture
ROOT=fixture.ROOT;OUT=fixture.OUT;RELEASE=ROOT/'deploy/full-function/d10-release'
def need(ok,message):
    if not ok:raise RuntimeError(message)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,value):p.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
def main():
    native=json.loads((OUT/'native.json').read_text())
    need(len(native['cases'])==18 and all(c['status']=='PASS' for c in native['cases']),'NATIVE_INCOMPLETE')
    native_config=json.loads((OUT/'native-config.json').read_text());need(native_config['status']=='PASS','NATIVE_CONFIG_INCOMPLETE')
    classes={}
    for name in ('d10-risk-targeted.log','d10-portal-targeted.log','d10-portal-strict-final.log','d10-gateway-targeted.log','d10-spi-targeted.log'):
        for cls in re.findall(r'-- in ([\w.]+)',(ROOT/'target'/name).read_text(encoding='utf-8',errors='replace')):
            candidates=[p for base in (ROOT/'target',ROOT/'risk-scoring-service/target',ROOT/'gateway/target',ROOT/'keycloak-risk-extension/target') for p in (base/'surefire-reports'/('TEST-'+cls+'.xml'),) if p.exists()]
            need(len(candidates)==1,'TEST_XML_MISSING_OR_AMBIGUOUS')
            p=candidates[0];r=ET.parse(p).getroot();entry={k:int(r.attrib[k]) for k in ('tests','failures','errors','skipped')};entry['xml']=p.relative_to(ROOT).as_posix();entry['sha256']=sha(p)
            need(entry['failures']==entry['errors']==entry['skipped']==0,'TARGETED_TEST_NOT_PASS');classes[cls]=entry
    java=sum(c['tests'] for c in classes.values());need(java==457,'TEST_COUNT_CHANGED_REVIEW')
    ui=(ROOT/'target/d10-frontend-tests.log').read_text(encoding='utf-8');need('tests 12' in ui and 'fail 0' in ui,'FRONTEND_TEST_NOT_PASS')
    before=json.loads((OUT/'preservation-before.json').read_text());after=fixture.snapshot();need(after==before,'ACTIVE_PRESERVATION_FAILED');write(OUT/'preservation-after.json',after)
    preflight=json.loads((ROOT/'target/full-function-20261111b/post-cutover-functional-acceptance-20261113/preflight.json').read_text())
    active={}
    for role,row in preflight['runtime'].items():
        key='/'+row['name'];need(key in after and after[key]['image']==row['image'] and after[key]['running'],'ACTIVE_PIN_OR_RUNNING_DRIFT');active[role]=after[key]
    need(len(active)==9,'ACTIVE_INVENTORY_COUNT')
    sql='SELECT version,checksum,success FROM pd_staging_risk.flyway_schema_history ORDER BY installed_rank'
    result=subprocess.run(['docker','exec','zt-full-function-20261111b-mysql-1','mysql','--defaults-extra-file=/fixture/root.cnf','-Nse',sql],capture_output=True,text=True,timeout=20)
    need(result.returncode==0,'ACTIVE_READONLY_LEDGER_FAILED');ledger=result.stdout.strip();need([r.split('\t')[0] for r in ledger.splitlines()]==list('1234567'),'ACTIVE_NOT_V7')
    images={}
    jar_paths={'risk':'risk-scoring-service/target/risk-scoring-service-0.0.1-SNAPSHOT.jar','backend':'target/zerotrust-0.0.1-SNAPSHOT.jar','gateway':'gateway/target/zerotrust-gateway-0.0.1-SNAPSHOT.jar','keycloak':'keycloak-risk-extension/target/keycloak-risk-extension.jar'}
    for role in ('risk','backend','gateway','keycloak','frontend'):
        artifact=json.loads((OUT/(role+'-artifact.json')).read_text());observed=fixture.run('docker','image','inspect','--format','{{.Id}}',artifact['image']).stdout.strip();need(observed==artifact['id'],'IMAGE_DRIFT')
        if role in jar_paths:need(sha(ROOT/jar_paths[role])==artifact['jar_sha256'],'JAR_DRIFT')
        images[role]=artifact
    preservation={'status':'PASS','compared_non_fixture_containers':len(before),'compared_fields':['id','image','started','running','restarts'],'active_nine':active,'active_flyway_ledger':ledger,'schema':7,'previous_acceptance':'reused; no owner login/reset repeated','protected_table_hashes':'16 PASS reused from existing acceptance; not re-exported'}
    verification={'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'offline_status':'PASS','policy':'B selected by owner for offline engineering only','java':{'tests':java,'failures':0,'errors':0,'skipped':0,'classes':classes},'frontend':{'tests':12,'failures':0,'typecheck':'PASS','production_build':'PASS','node':'24.22.2','npm':'11.21.2','new_reset_spa_e2e':'NOT_RUN; native protocol and actual Portal guard tested'},'total_targeted_tests':java+12,'native':{'cases':18,'failures':0,'evidence':'target/d10-phase2-20261113/native.json','environment':'disposable local-JPA Keycloak 26.8.2 / TLS MySQL Redis real APIs; synthetic accounts only','wall_clock_sso_8h_expiry':'NOT_WAIT_TESTED; effective configuration verified'},'migration':{'status':'PASS','evidence':['target/d10-phase2-20261113/migration.json','target/d10-phase2-20261113/migration-latest.json'],'active_mutated':False},'preservation':preservation,'images':images,'D10':'UNRESOLVED_UNTIL_DEPLOYED_NATIVE_ACCEPTANCE','D17':'PENDING','G8':'INTERNET_NO_GO','public_network_calibration':'PENDING'}
    write(OUT/'verification.json',verification)
    files={}
    source_roots=('src/main','src/test','risk-scoring-service/src','keycloak-risk-extension/src','gateway/src','frontend/components','frontend/lib','frontend/tests','keycloak-theme/zerotrust')
    for root in source_roots:
        for p in (ROOT/root).rglob('*'):
            if p.is_file() and p.suffix in ('.java','.properties','.sql','.tsx','.ts','.mjs','.html','.css','.ftl','.xml') or p.is_file() and 'META-INF/services/' in p.as_posix():files[p.relative_to(ROOT).as_posix()]=sha(p)
    for path in ('pom.xml','risk-scoring-service/pom.xml','keycloak-risk-extension/pom.xml','gateway/pom.xml','frontend/package.json','frontend/package-lock.json','deploy/full-function/d10_native_check.py','deploy/full-function/d10_isolated.py','deploy/full-function/d10_evidence.py','deploy/full-function/d10-release/contract.json','deploy/full-function/d10-release/validate.py',*jar_paths.values()):files[path]=sha(ROOT/path)
    for name in ('verification.json','native.json','native.log','native-config.json','migration.json','migration-latest.json','preservation-before.json','preservation-after.json'):
        p=OUT/name;files[p.relative_to(ROOT).as_posix()]=sha(p)
    binding={'purpose':'D10_OFFLINE_RELEASE','version':1,'created_utc':verification['created_utc'],'offline_status':'PASS','deployment_authorized':False,'registry_published':False,'target_project':'zt-full-function-20261111b','verification':'target/d10-phase2-20261113/verification.json','images':images,'files':files,'phase3_required':['owner controlled-deployment authorization','separate reviewed maintenance executor/checkpoint','target config/flow/role/TLS binding and reserved-attribute check','native acceptance on deployed runtime'],'rollback':'no epoch/pending/tombstone/credential/trust restore; maintenance fail-closed until strict-compatible artifact'}
    write(RELEASE/'binding.offline.json',binding)
    print(f'PASS {java+12} targeted tests + 18 native cases; exact preservation of {len(active)} active services and {len(before)} non-fixture containers; D10 offline binding sealed, no deployment authorization')
if __name__=='__main__':main()
