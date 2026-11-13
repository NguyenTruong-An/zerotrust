"""Read-only preservation/maintenance verification plus isolated helper-name smoke."""
import datetime,json
from pathlib import Path
from executor import Executor,ROOT,inspect,need,run,sha,write
from operation import helper
OUT=ROOT/'target/d10-phase3-20261113'

def main():
    before=json.loads((OUT/'preservation-before.json').read_text())
    ids=run('docker','ps','-aq').decode().split()
    fmt='{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"started":{{json .State.StartedAt}},"running":{{json .State.Running}},"restarts":{{json .RestartCount}}}'
    after={r['name']:r for r in (json.loads(line) for line in run('docker','inspect','--format',fmt,*ids).decode().splitlines()) if not r['name'].startswith(('/zt-d10-offline-20261113-','/zt-d10-rollout-rehearsal-20261113'))}
    need(before==after,'NON_D10_CONTAINER_STATE_CHANGED')
    write(OUT/'preservation-after.json',after)
    folder=OUT/'rehearsal-final2';plan=json.loads((folder/'execution-plan.json').read_text());e=Executor(plan,'rehearsal')
    evidence={}
    for role in ('risk','keycloak','backend','gateway','frontend'):
        old=inspect(e.old[role]);new=inspect(e.name(role))
        need(not old['State']['Running'] and new['State']['Running'],'WRITER_EXCLUSIVITY')
        need(old['State']['FinishedAt']<new['Created'],'OLD_AND_NEW_WRITER_OVERLAP')
        need(not new['HostConfig'].get('PortBindings'),'PUBLISHED_GATE_PORT')
        evidence[role]={'old_stopped_at':old['State']['FinishedAt'],'new_created_at':new['Created'],'new_image':new['Image'],'published_ports':0}
    public=inspect(e.name('public-ingress'));receipt=e.out/'native-acceptance.json'
    created=datetime.datetime.fromisoformat(public['Created'].replace('Z','+00:00')).timestamp()
    need(created>=receipt.stat().st_mtime,'PUBLIC_CREATED_BEFORE_ACCEPTANCE')
    need(e.j['phase']=='OPEN_STRICT' and not inspect(e.old['ingress'])['State']['Running'],'OLD_INGRESS_REOPENED')
    need(not public['HostConfig'].get('PortBindings'),'REHEARSAL_HOST_LISTENER')
    need('HOLD_FAIL_CLOSED'in e.j['evidence'],'HOLD_NOT_REHEARSED')
    write(OUT/'maintenance-proof.json',{'status':'PASS','scope':'final2 disposable only; structural and timestamp evidence, not continuous packet capture','roles':evidence,'old_ingress_stopped':True,'public_created_after_positive_acceptance':True,'rehearsal_host_ports':0,'hold_repair':e.j['evidence']['HOLD_FAIL_CLOSED'],'no_old_V7_restart':True,'source_211_containers_unchanged':len(after)==211})
    name=helper(e,folder/'public',e.out)
    try:
        archive=e.archive_volume(plan['config_volumes']['ingress'])
        need(inspect(name)['State']['Running'] and len(archive)>0,'HELPER_COLLISION')
        write(OUT/'helper-smoke.json',{'status':'PASS','scope':'final2 disposable; no live mounts','acceptance_helper':name,'archive_helper':e.name('helper'),'concurrent_distinct_names':True,'archive_sha256':sha(archive),'tokens_saved':False})
    finally:e.stop(name)
    print('PASS preservation '+str(len(after))+' existing containers; maintenance ordering; isolated concurrent acceptance/archive helpers')
if __name__=='__main__':main()
