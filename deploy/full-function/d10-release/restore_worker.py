"""Independent decrypt/restore verifier. Only a newly labelled, network-none restore DB."""
import json,re,sys,time
from pathlib import Path
from executor import Checkpoint,ROOT,canonical,inspect,need,run,sha
from cryptography.exceptions import InvalidTag
def canonical_sql(data):
    # MySQL8.4 may add an explicit CHARACTER SET after restoring SHOW CREATE output.
    # utf8mb4_* COLLATE already implies utf8mb4. Only normalize column DDL, never data.
    data=re.sub(rb'(?m)^(  `[^`]+` [^\r\n]*?) CHARACTER SET utf8mb4( COLLATE utf8mb4_[^\r\n]*)$',rb'\1\2',data)
    # The two nullable Keycloak tinyint columns may gain explicit DEFAULT NULL.
    return re.sub(rb'(?m)^(  `[^`]+` tinyint(?:\(\d+\))?) DEFAULT NULL(,?)$',rb'\1\2',data)
def main():
    plan=json.loads(Path(sys.argv[1]).read_text());target=sys.argv[2];runid=plan['run_id'];project=plan['project']
    need(target==project+'-d10-restore-mysql-'+runid,'RESTORE_TARGET_NAME')
    x=inspect(target);labels=x['Config']['Labels'] or {}
    need(labels.get('io.zerotrust.d10.run')==runid and labels.get('io.zerotrust.d10.project')==project,'RESTORE_TARGET_LABEL')
    need(x['HostConfig']['NetworkMode']=='none' and not x['HostConfig'].get('PortBindings'),'RESTORE_MUST_BE_ISOLATED')
    need(all(m['Type']=='volume' and m['Name'].startswith(project+'_d10_'+runid+'_restore-') for m in x['Mounts']),'RESTORE_MOUNT_SCOPE')
    folder=ROOT/plan['output'];cp=Checkpoint(folder/'checkpoint',sha(canonical(plan)));dump=cp.unseal('sql')
    # A corrupted backup must fail authentication before MySQL receives anything.
    encrypted=(folder/'checkpoint/sql.aesgcm').read_bytes();broken=bytearray(encrypted);broken[-1]^=1
    try:cp.cipher.decrypt(bytes(broken[:12]),bytes(broken[12:]),cp.aad+b':sql');raise RuntimeError('CORRUPT_BACKUP_ACCEPTED')
    except InvalidTag:pass
    # TCP is unavailable during entrypoint's TEMPORARY initialization server.
    # Waiting on its socket would race init.sql and could destroy the fresh schema mid-init.
    # A network-none container resolves mysql to loopback; TLS still verifies the mysql SAN.
    need('mysql:127.0.0.1' in (x['HostConfig'].get('ExtraHosts') or []),'RESTORE_LOOPBACK_HOST_REQUIRED')
    base=['docker','exec','-i',target,'mysql','--defaults-extra-file=/fixture/root.cnf','--protocol=TCP','--host=mysql']
    deadline=time.monotonic()+150
    while True:
        try:run(*base,'-Nse','SELECT 1',timeout=6);break
        except Exception:
            need(time.monotonic()<deadline,'RESTORE_DATABASE_NOT_READY');time.sleep(1)
    run(*base,data=dump,timeout=180)
    redump=run('docker','exec',target,'mysqldump','--defaults-extra-file=/fixture/root.cnf','--protocol=TCP','--host=mysql','--single-transaction','--set-gtid-purged=OFF','--no-tablespaces','--hex-blob','--skip-comments','--skip-dump-date','--order-by-primary','--add-drop-database','--databases','pd_staging_school','pd_staging_risk','pd_staging_keycloak',timeout=180)
    need(sha(canonical_sql(redump))==sha(canonical_sql(dump)),'RESTORED_SQL_CONTENT_DIFFERS')
    # Independently require all INSERT bytes to match exactly; no normalization touches credentials/data.
    rows=lambda raw:b'\n'.join(line for line in raw.splitlines() if line.startswith(b'INSERT INTO '))
    need(rows(redump)==rows(dump),'RESTORED_ROW_BYTES_DIFFER')
    from executor import write
    write(folder/'restore-proof.json',{'status':'PASS','source_sql_sha256':sha(dump),'restored_sql_sha256':sha(redump),'canonical_sql_sha256':sha(canonical_sql(dump)),'insert_bytes_equal':True,'normalization':['column DDL redundant CHARACTER SET utf8mb4 before utf8mb4 COLLATE','nullable tinyint explicit DEFAULT NULL'],'corrupt_tag_rejected':True,'network':'none','published_ports':0,'plaintext_sql_file':False})
    print('PASS independent AES-GCM/DPAPI decrypt, corrupt-tag rejection, exact INSERT bytes and canonical DDL; no plaintext SQL file')
if __name__=='__main__':
    try:main()
    except Exception as e:print('FAIL '+(str(e) if isinstance(e,RuntimeError) else type(e).__name__),file=sys.stderr);sys.exit(1)
