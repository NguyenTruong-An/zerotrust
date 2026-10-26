"""Prepare exact destinations/hashes and an unapproved token. Does not execute persistent mutations."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import ssl
import subprocess

ROOT=Path(__file__).resolve().parents[2]
PROJECT='zerotrust-legacy-integration-20261026'


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--private',type=Path,required=True);args=parser.parse_args()
    source=args.source;private=args.private;state=private/'runtime'
    assert not (state/'evidence/execution.private.json').exists(), 'EXECUTION_ALREADY_STARTED_DO_NOT_OVERWRITE_APPROVAL_OR_REIMPORT'
    manifest=json.loads((source/'execution/backup-execution.private.json').read_text())
    diagnosis=json.loads((private/'risk-readiness-diagnosis.private.json').read_text())
    rows=diagnosis['missing_state_rows'];assert len(rows)==1
    subject,count,statuses,reasons,audits=rows[0].split('\t')
    assert re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',subject)
    assert (count,statuses,reasons,audits)==('2','TRUSTED','NULL','0')
    subject_hash=hashlib.sha256(subject.encode()).hexdigest()
    reviewed=json.loads((private/'risk-readiness-summary.json').read_text())
    assert len(reviewed['missing_state'])==1 and subject_hash==reviewed['missing_state'][0]['subject_sha256']
    statement=("-- PROPOSAL ONLY. Exactly one generation-zero row on the NEW COPY, requiring explicit approval.\n"
        "INSERT INTO risk_db.subject_device_trust(subject_id,generation,pending_operation_id) "
        "SELECT '"+subject+"',0,NULL WHERE NOT EXISTS (SELECT 1 FROM risk_db.subject_device_trust WHERE BINARY subject_id=BINARY '"+subject+"') "
        "AND NOT EXISTS (SELECT 1 FROM risk_db.device_trust_revocations WHERE BINARY subject_id=BINARY '"+subject+"') "
        "AND 2=(SELECT COUNT(*) FROM risk_db.known_devices WHERE BINARY subject_id=BINARY '"+subject+"' AND status='TRUSTED' AND revocation_reason IS NULL);\n")
    sql_file=state/'risk-db/generation-reconciliation.private.sql';sql_file.write_text(statement)
    query=("SELECT (SELECT COUNT(*) FROM risk_db.known_devices WHERE BINARY subject_id=BINARY '"+subject+"' AND status='TRUSTED' AND revocation_reason IS NULL),"
           "(SELECT COUNT(*) FROM risk_db.device_trust_revocations WHERE BINARY subject_id=BINARY '"+subject+"'),"
           "(SELECT COUNT(*) FROM risk_db.subject_device_trust WHERE BINARY subject_id=BINARY '"+subject+"')")
    result=subprocess.run(['git','diff','--name-only','-z','HEAD'],cwd=ROOT,capture_output=True,check=True)
    files=set(result.stdout.decode().split('\0'))-{''}
    result=subprocess.run(['git','ls-files','--others','--exclude-standard','-z'],cwd=ROOT,capture_output=True,check=True)
    files.update(set(result.stdout.decode().split('\0'))-{''})
    source_files={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sorted(files) if (ROOT/name).is_file()}
    images={}
    for name in ['backend','risk','frontend','gateway','keycloak','keycloak-import','tools']:
        tag='zerotrust-legacy-'+name+':20261026-candidate'
        obj=json.loads(subprocess.run(['docker','image','inspect',tag],capture_output=True,check=True).stdout)[0]
        images[name]={'tag':tag,'ID':obj['Id']}
    migration='database/migrations/school/V20261026_01__legacy_teacher_schedule.sql'
    ca_pem=(state/'public-ca/ca.crt').read_bytes()
    ca_der=ssl.PEM_cert_to_DER_cert(ca_pem.decode())
    plan={'project':PROJECT,'baseline':'8e10c1f902f3efeb899792cb91dc4cbfaa0e3708','private_state':str(state),
          'source_files':source_files,'private_files':{f.relative_to(state).as_posix():hashlib.sha256(f.read_bytes()).hexdigest() for f in state.rglob('*') if f.is_file() and f.relative_to(state).parts[0] not in ['approval','evidence']},'images':images,'backups':{k:{'file':v['file'],'sha256':v['sha256'],'bytes':v['bytes']} for k,v in manifest['steps'].items()},
          'volumes':[PROJECT+'_'+v for v in ['school-data','risk-db-data','keycloak-db-data','redis-data']],
          'networks':[PROJECT+'_core',PROJECT+'_edge'],
          'containers':[PROJECT+'-'+v for v in ['school','risk-db','keycloak-db','redis','keycloak','risk','backend','frontend','gateway','crl']],
          'school_migration_sha256':hashlib.sha256((ROOT/migration).read_bytes()).hexdigest(),
          'risk_reconciliation_assertion_sql':query,'risk_reconciliation_sql_sha256':hashlib.sha256(sql_file.read_bytes()).hexdigest(),
          'risk_missing_state_subject_sha256':subject_hash,'risk_added_rows_if_approved':1,
          'transport_CA_thumbprint_sha1':hashlib.sha1(ca_der).hexdigest().upper(),
          'transport_CA_PEM_SHA256':hashlib.sha256(ca_pem).hexdigest(),
          'CA_scope':'Docker/Java/private QA-browser stores only; no Windows Root installation',
          'budgets':{'new_persistent_volumes':4,'new_networks':2,'steady_containers':10,'migration_helper_memory_MiB':512,
                     'verification_helper_memory_MiB':128,'interactive_logins_max':12,'admin_configuration_logins_max':2,
                     'focused_HTTP_requests_max':300,'minutes_max':90,'candidate_data_GiB_max':4},
          'excluded':['source databases/containers/volumes','frozen restore mutation','fake teacher ownership',
                      'user recreation or MFA/password reset','V5 checksum or guard changes','source commit/push/cutover'],
          'status':'AWAITING_ONE_CONSOLIDATED_EXECUTION_APPROVAL'}
    file=private/'execution-plan.private.json';file.write_text(json.dumps(plan,indent=2))
    token={'approved':False,'project':PROJECT,'plan_sha256':hashlib.sha256(file.read_bytes()).hexdigest(),
           'school_migration_sha256':plan['school_migration_sha256'],'risk_generation_zero_backfill_approved':False,
           'Windows_Root_installation_permitted':False}
    (state/'approval/owner-approval.private.json').write_text(json.dumps(token,indent=2))
    print(json.dumps({'plan':str(file),'plan_sha256':token['plan_sha256'],'public_source_paths':len(source_files),
                      'persistent_execution_approved':False,'risk_reconciliation_approved':False},indent=2))


if __name__=='__main__':main()
