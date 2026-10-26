"""Materialize private, reviewable import/grant inputs; never execute SQL or call Keycloak."""
import hashlib
import json
from pathlib import Path, PureWindowsPath
import shutil
import secrets
import tarfile


def complete(source, state, assets=None):
    assert not (state/'evidence/execution.private.json').exists(), 'REHEARSAL_ALREADY_STARTED_NO_REPREPARE'
    cfg = json.loads((state/'credentials.private.json').read_text())
    pw = cfg['passwords']
    if 'risk-migrator' not in pw:
        pw['risk-migrator']=secrets.token_urlsafe(30)
        (state/'credentials.private.json').write_text(json.dumps(cfg,indent=2))
    def save(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2) if isinstance(value, (dict, list)) else value)
        path.chmod(0o600)
    import_assets=state/'import-assets';import_assets.mkdir(exist_ok=True)
    provider=source/'keycloak-files/providers/keycloak-risk-extension.jar'
    assert hashlib.sha256(provider.read_bytes()).hexdigest()=='3978e3615034208ed6e92efd74ffd9c51767f9249fbfba02a0464506a38de09d'
    shutil.copyfile(provider,import_assets/'keycloak-risk-extension.jar')
    theme=source/'keycloak-files/themes/zerotrust'
    with tarfile.open(import_assets/'legacy-theme.tar','w') as archive:
        for file in sorted(theme.rglob('*')):
            if file.is_file():
                assert not file.is_symlink()
                archive.add(file,arcname='zerotrust/'+file.relative_to(theme).as_posix(),recursive=False)
    for name in ['approval','evidence']:(state/name).mkdir(exist_ok=True)
    approval=state/'approval/owner-approval.private.json'
    if not approval.exists():
        save(approval,{'approved':False,'project':cfg['owner'],'school_migration_sha256':'FILL_FROM_REVIEWED_SOURCE',
                       'risk_generation_zero_backfill_approved':False})
    tables=['scores','student_classes','students','subjects','users','teachers','teaching_assignments','schedule_entries']
    sql="CREATE USER 'legacy_school'@'%' IDENTIFIED BY '"+pw['school']+"' REQUIRE SSL;\n"
    sql+="CREATE USER 'legacy_school_migrator'@'%' IDENTIFIED BY '"+pw['school-migrator']+"' REQUIRE SSL;\n"
    sql+="GRANT SELECT,CREATE,ALTER,INDEX,REFERENCES,INSERT ON vip_pro.* TO 'legacy_school_migrator'@'%';\n"
    # The app can access future teaching tables only after the migration creates them.
    sql+=''.join("GRANT SELECT,INSERT,UPDATE,DELETE ON vip_pro.`"+t+"` TO 'legacy_school'@'%';\n" for t in tables[:5])
    save(state/'school/grants-before.private.sql',sql)
    save(state/'school/grants-after.private.sql',''.join("GRANT SELECT,INSERT,UPDATE,DELETE ON vip_pro.`"+t+"` TO 'legacy_school'@'%';\n" for t in tables[5:]))
    save(state/'keycloak-db/initialize.private.sql',
        "CREATE DATABASE keycloak_legacy CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
        "CREATE USER 'legacy_keycloak'@'%' IDENTIFIED BY '"+pw['keycloak']+"' REQUIRE SSL;\n"
        "GRANT ALL PRIVILEGES ON keycloak_legacy.* TO 'legacy_keycloak'@'%';\n")
    save(state/'risk-db/grants.private.sql',
        "ALTER USER 'risk_service'@'%' REQUIRE SSL;\nREVOKE ALL PRIVILEGES, GRANT OPTION FROM 'risk_service'@'%';\n"
        "GRANT SELECT ON risk_db.flyway_schema_history TO 'risk_service'@'%';\n"
        "GRANT SELECT,INSERT,UPDATE,DELETE ON risk_db.known_devices TO 'risk_service'@'%';\n"
        "GRANT SELECT,INSERT,UPDATE,DELETE ON risk_db.authentication_success_events TO 'risk_service'@'%';\n"
        "GRANT SELECT,INSERT,UPDATE ON risk_db.subject_device_trust TO 'risk_service'@'%';\n"
        "GRANT SELECT,INSERT,UPDATE ON risk_db.device_trust_revocations TO 'risk_service'@'%';\n")
    containers=json.loads((source/'runtime/docker-inspect.private.json').read_text())
    original=next(c for c in containers if c['Name']=='/keycloak-26.7.0')
    env=dict(v.split('=',1) for v in original['Config']['Env'])
    save(state/'approval/admin-credentials.private.json',
         {'username':env['KEYCLOAK_ADMIN'],'password':env['KEYCLOAK_ADMIN_PASSWORD']})
    save(state/'risk-db/migrator-grants.private.sql',
        "CREATE USER 'legacy_risk_migrator'@'%' IDENTIFIED BY '"+pw['risk-migrator']+"' REQUIRE SSL;\n"
        "GRANT ALL PRIVILEGES ON risk_db.* TO 'legacy_risk_migrator'@'%';\n"
        "GRANT SELECT ON performance_schema.threads TO 'legacy_risk_migrator'@'%';\n")
    migration=state/'migrate/migration.properties'
    text=migration.read_text().replace('username=root','username=legacy_risk_migrator').replace('password='+pw['risk-root'],'password='+pw['risk-migrator'])
    save(migration,text)
    for role in ['school','risk-db','keycloak-db']:
        file=state/role/'client.cnf'
        save(file,file.read_text().replace('host='+role,'host=localhost\nprotocol=TCP'))
    policy=state/'risk/legacy-policy.env'
    values={}
    for line in policy.read_text().splitlines():
        if '=' in line:
            key,value=line.split('=',1);values[key]=value
    if values.get('RISK_GEOIP_ENABLED','false').lower()=='true':
        assert assets is not None, 'ORIGINAL_GEOIP_ASSETS_REQUIRED_NO_SILENT_DISABLE'
        for name,variable in [('city','RISK_GEOIP_CITY_DATABASE_PATH'),('asn','RISK_GEOIP_ASN_DATABASE_PATH')]:
            file=assets/(name+'.mmdb');assert file.is_file() and not file.is_symlink()
            directory=state/'risk/geoip';directory.mkdir(exist_ok=True)
            shutil.copyfile(file,directory/file.name)
            values[variable]='/run/demo/geoip/'+file.name
        save(policy,''.join(key+'='+value+'\n' for key,value in values.items()))
    old=json.loads((source/'execution/backup-execution.private.json').read_text())
    save(state/'input-backup-manifest.private.json',{'source_root':str(source),
         'backup_files':{k:{'file':PureWindowsPath(v['file']).name,'bytes':v['bytes'],'sha256':v['sha256']} for k,v in old['steps'].items()}})
    print('Private grant/import assets materialized. No SQL or import executed.')


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True);parser.add_argument('--state',type=Path,required=True);parser.add_argument('--assets',type=Path)
    args=parser.parse_args();complete(args.source,args.state,args.assets)
