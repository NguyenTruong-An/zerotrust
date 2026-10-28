"""Bounded new-copy orchestration. Default is a plan check; execution needs explicit owner approval."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

PROJECT = 'zerotrust-legacy-integration-20261026'
ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['check', 'execute'])
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--approval', type=Path)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    assert plan['project'] == PROJECT and plan['baseline'] == '8e10c1f902f3efeb899792cb91dc4cbfaa0e3708'
    assert plan.get('scope') == 'score-portal-admin-student' and plan.get('school_schema_change') is False, 'REVIEW_SCORE_PORTAL_PLAN_REQUIRED'
    state = Path(plan['private_state']); evidence = state/'evidence'; evidence.mkdir(exist_ok=True)
    for file, expected in plan['source_files'].items():
        assert hashlib.sha256((ROOT/file).read_bytes()).hexdigest() == expected, 'REVIEWED_SOURCE_CHANGED'
    for file, expected in plan.get('private_files', {}).items():
        assert hashlib.sha256((state/file).read_bytes()).hexdigest()==expected, 'REVIEWED_PRIVATE_CONFIG_CHANGED'
    for item in plan['backups'].values():
        file = Path(item['file'])
        with file.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        assert digest == item['sha256'], 'BACKUP_HASH_DRIFT'
    def read(command, checked=True):
        result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=45)
        if checked and result.returncode:
            (evidence/'read-error.private.log').write_bytes(result.stdout+result.stderr)
            raise RuntimeError('READ_FAILED; private log retained')
        return result
    for image in plan['images'].values():
        actual=json.loads(read(['docker','image','inspect',image['tag']]).stdout)[0]
        assert actual['Id'] == image['ID'], 'IMAGE_TAG_DRIFT'
    if args.action == 'check':
        print(json.dumps({'status':'PLAN_CHECK_PASS','persistent_mutations':0,
                          'approval_required_for_execution':True,'project':PROJECT}))
        return
    assert args.approval, 'OWNER_EXECUTION_APPROVAL_REQUIRED'
    approval=json.loads(args.approval.read_text())
    assert approval.get('approved') is True and approval['project']==PROJECT
    assert approval['plan_sha256']==hashlib.sha256(args.plan.read_bytes()).hexdigest(), 'APPROVAL_PLAN_DRIFT'
    assert approval.get('risk_generation_zero_backfill_approved') is True, 'RISK_RECONCILIATION_DECISION_REQUIRED'
    assert approval.get('scope') == plan['scope'], 'APPROVAL_SCOPE_DRIFT'
    authorization=state/'approval/owner-approval.private.json'
    if args.approval.resolve()!=authorization.resolve():authorization.write_bytes(args.approval.read_bytes())
    journal=evidence/'execution.private.json'
    assert not journal.exists(), 'EXECUTION_ALREADY_STARTED; review checkpoint, never overwrite a partial database'
    j={'project':PROJECT,'plan_sha256':approval['plan_sha256'],'steps':[],'source_resources_modified':False}
    def save():journal.write_text(json.dumps(j,indent=2))
    save()
    for volume in plan['volumes']:
        assert read(['docker','volume','inspect',volume],False).returncode!=0, 'DESTINATION_VOLUME_ALREADY_EXISTS'
    for network in plan['networks']:
        assert read(['docker','network','inspect',network],False).returncode!=0, 'DESTINATION_NETWORK_ALREADY_EXISTS'
    for name in plan['containers']:
        assert read(['docker','inspect',name],False).returncode!=0, 'DESTINATION_CONTAINER_ALREADY_EXISTS'
    compose=['docker','compose','--project-name',PROJECT,'--project-directory',str(ROOT),'--env-file',str(args.plan.parent/'compose.private.env'),
             '-f',str(ROOT/'compose.legacy.yaml'),'--profile','legacy','--profile','migration']
    def run(command, label, stream=None, timeout=240):
        with (evidence/(label+'.private.log')).open('wb') as log:
            result=subprocess.run(command,cwd=ROOT,stdin=stream,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
        if result.returncode:raise RuntimeError(label+' FAILED; retain target/evidence, no repair/clean')
        j['steps'].append(label);save()
    def sql(service, statement=None, file=None, label='sql'):
        name=PROJECT+'-'+service
        assert name in plan['containers']
        command=['docker','exec','-i',name,'mysql','--defaults-extra-file=/tmp/legacy-client.cnf',
                 '--batch','--raw','--skip-column-names']
        if statement is not None:return read(command+['--execute',statement]).stdout.decode('utf-8-sig').strip()
        with Path(file).open('rb') as stream:run(command,label,stream=stream)
    def volume_owner(name):
        assert name in plan['volumes']
        info=json.loads(read(['docker','volume','inspect',name]).stdout)[0]
        assert info['Labels'].get('app.owner')==PROJECT, 'TARGET_VOLUME_OWNERSHIP_MISMATCH'
    # create does not start engines. The nocopy target volumes must still be empty for extraction.
    tools=plan['images']['tools']['tag']
    # NTFS access stays restricted to the owner/SYSTEM. Scoped read-only binds must
    # also be readable by the images' non-root users; never expose authority/approval.
    permission_code=("from pathlib import Path;import os;roles=['school','risk-db','keycloak-db','redis',"
        "'backend','risk','gateway','keycloak','migrate','public-ca','migration-inputs'];"
        "[os.chmod(f,0o644) for r in roles for f in Path('/state',r).rglob('*') if f.is_file()];"
        "p=Path('/state/evidence/keycloak-post-import');p.mkdir(exist_ok=True);os.chmod(p,0o777)")
    run(['docker','run','--rm','--name',PROJECT+'-runtime-permissions','--network','none','--read-only','--memory','128m',
         '--mount','type=bind,src='+str(state)+',dst=/state','--entrypoint','/opt/tools/bin/python',tools,'-c',permission_code],
         'prepare-scoped-runtime-bind-permissions')
    run(compose+['create','school','risk-db','redis','keycloak-db'],'create-new-databases')
    for name in plan['volumes']:volume_owner(name)
    for service, backup in [('risk-db','risk'),('redis','redis')]:
        archive=Path(plan['backups'][backup]['file'])
        run(['docker','run','--rm','--name',PROJECT+'-copy-'+service,'--network','none','--read-only','--memory','256m',
             '--label','app.owner='+PROJECT,'--mount','type=volume,src='+PROJECT+'_'+service+'-data,dst=/target,volume-nocopy',
             '--mount','type=bind,src='+str(archive.parent)+',dst=/backup,readonly',
             '--mount','type=bind,src='+str(ROOT/'scripts/legacy/archive_volume.py')+',dst=/archive.py,readonly',
             '--entrypoint','/opt/tools/bin/python',tools,'/archive.py','unpack','/backup/'+archive.name,'/target'],
             'copy-'+service)
    run(compose+['up','-d','--no-deps','school','risk-db','redis','keycloak-db'],'start-new-databases')
    for service in ['school','risk-db','redis','keycloak-db']:
        for attempt in range(48):
            info=json.loads(read(['docker','inspect',PROJECT+'-'+service]).stdout)[0]
            if info['State'].get('Health',{}).get('Status')=='healthy':break
            assert info['State']['Running'], 'CANDIDATE_DATABASE_EXITED'
            time.sleep(3)
        else:raise RuntimeError('CANDIDATE_DATABASE_HEALTH_TIMEOUT')
    for service,version in [('school','9.1.0'),('risk-db','8.0.46'),('keycloak-db','8.4.13')]:
        assert sql(service,'SELECT @@version').startswith(version), 'TARGET_ENGINE_VERSION_DRIFT'
    assert sql('school',"SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='vip_pro'")=='0'
    assert sql('keycloak-db',"SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='keycloak_legacy'")=='0'
    sql('school',file=plan['backups']['school']['file'],label='import-school-backup')
    sql('school',file=state/'school/grants-before.private.sql',label='school-application-and-readonly-validation-grants')
    run(compose+['run','--rm','--no-deps','--name',PROJECT+'-school-check','school-check'],'school-readonly-validation')
    sql('keycloak-db',file=state/'keycloak-db/initialize.private.sql',label='fresh-keycloak-database-grants')
    run(compose+['run','--rm','--no-deps','--name',PROJECT+'-keycloak-import','keycloak-import'],'official-keycloak-import')
    run(compose+['run','--rm','--no-deps','--name',PROJECT+'-keycloak-export','keycloak-export'],'official-keycloak-export')
    run(['docker','run','--rm','--name',PROJECT+'-model-check','--network','none','--read-only','--memory','128m',
         '--mount','type=bind,src='+str(state)+',dst=/state','--mount','type=bind,src='+str(ROOT)+',dst=/candidate,readonly',
         '--entrypoint','/opt/tools/bin/python',tools,'/candidate/scripts/legacy/compare_keycloak_exports.py',
         '/state/migration-inputs/keycloak/original-export','/state/evidence/keycloak-post-import','--report','/state/evidence/keycloak-import-comparison.json'],
         'compare-keycloak-identities-and-credentials')
    target_realm=json.loads((state/'evidence/keycloak-post-import/DoAn-realm.json').read_text(encoding='utf-8'))
    school_subjects=sql('school','SELECT BIN_TO_UUID(keycloak_user_id) FROM vip_pro.users').splitlines()
    assert len(school_subjects)==6 and len(set(school_subjects))==6
    assert all(subject in {u['id'] for u in target_realm['users']} for subject in school_subjects), 'SCHOOL_KEYCLOAK_MAPPING_DRIFT'
    (evidence/'school-keycloak-mapping.json').write_text(json.dumps({'source_subjects':6,'matching_original_DoAn_users':6}))
    sql('risk-db',file=state/'risk-db/migrator-grants.private.sql',label='scoped-risk-migrator-grants')
    # Exact, owner-approved data reconciliation only; no aliases/remaps/deletions, and never on frozen sources.
    assert sql('risk-db',"SELECT COUNT(*) FROM risk_db.subject_device_trust")== '7'
    before=sql('risk-db',plan['risk_reconciliation_assertion_sql'])
    assert before=='2\t0\t0', 'RECONCILIATION_PRECONDITION_DRIFT'
    assert hashlib.sha256((state/'risk-db/generation-reconciliation.private.sql').read_bytes()).hexdigest()==plan['risk_reconciliation_sql_sha256']
    sql('risk-db',file=state/'risk-db/generation-reconciliation.private.sql',label='approved-single-generation-zero-row')
    assert sql('risk-db',"SELECT COUNT(*) FROM risk_db.subject_device_trust")=='8'
    migration=state/'migrate/migration.properties'
    content=migration.read_text();assert 'owner.execution.approved=false' in content
    migration.write_bytes(content.replace('owner.execution.approved=false','owner.execution.approved=true').encode())
    run(compose+['run','--rm','--no-deps','--name',PROJECT+'-risk-migrate','risk-migrate'],'immutable-risk-V5-migration')
    sql('risk-db',file=state/'risk-db/grants.private.sql',label='risk-application-grants')
    assert sql('risk-db',"SELECT checksum FROM risk_db.flyway_schema_history WHERE version='5' AND success=1")=='661092940'
    run(compose+['up','-d','--no-deps','crl','keycloak'],'start-keycloak-TLS')
    # Wait for readiness before the one permitted copy configuration login.
    for attempt in range(48):
        info=json.loads(read(['docker','inspect',PROJECT+'-keycloak']).stdout)[0]
        if info['State'].get('Health',{}).get('Status')=='healthy':break
        assert info['State']['Running'],'KEYCLOAK_EXITED'
        time.sleep(3)
    else:raise RuntimeError('KEYCLOAK_READINESS_TIMEOUT')
    run(['docker','run','--rm','--name',PROJECT+'-copy-config','--network',PROJECT+'_core','--read-only','--memory','128m',
         '--mount','type=bind,src='+str(state)+',dst=/state','--mount','type=bind,src='+str(ROOT)+',dst=/candidate,readonly',
         '--entrypoint','/opt/tools/bin/python',tools,'/candidate/scripts/legacy/configure_keycloak_copy.py','--state','/state'],
         'copy-only-TLS-and-endpoint-configuration')
    run(compose+['up','-d','--wait','--wait-timeout','240','risk','backend','frontend','gateway'],'start-legacy-applications')
    j['Windows_CA_installation']='NOT_PERFORMED: use scoped Docker/Java/QA-browser trust only'

    j['status']='MIGRATION_REHEARSAL_READY_FOR_FOCUSED_BROWSER_API_VERIFICATION'
    j['LEGACY_DOCKER_INTEGRATION_VERIFIED']=False
    save()
    print(json.dumps({'status':j['status'],'manual_browser':'NOT_VERIFIED',
                      'scope':'score-portal-admin-student','project':PROJECT},indent=2))


if __name__=='__main__':main()
