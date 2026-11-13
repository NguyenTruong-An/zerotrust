"""Single D10 GO checkpoint and controlled execution. Default status is read-only."""
import argparse,datetime,json,secrets,subprocess,sys,time,uuid
from pathlib import Path
from executor import Executor,LIVE,ROOT,canonical,inspect,launch_hash,need,projection,run,sha,write
from operation import designated,generated_inputs,helper,monitor,native_process,protect_inputs,provisioner_secret,ready,rpc,stage_install,verify_state
HERE=Path(__file__).resolve().parent;OUT=ROOT/'target/d10-phase3-20261113';PLAN=HERE/'execution.live.PENDING.json'
def prepare():
    import packet
    packet.validate();pre=json.loads((OUT/'live-preflight.json').read_text());need((datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(pre['checked_utc'])).total_seconds()<1200,'LIVE_PREFLIGHT_STALE')
    need(not PLAN.exists(),'LIVE_PLAN_ALREADY_PREPARED')
    bound=json.loads((HERE/'binding.phase3.json').read_text());inventory=pre['inventory'];source={role:{k:row[k] for k in ('id','name','image','running','started','restarts','launch_sha256')} for role,row in inventory.items()}
    configs={}
    for role,row in inventory.items():
        for mount in row['mounts']:
            if mount['Type']=='volume' and mount['Destination']in ('/fixture','/run/demo','/run/secrets') and role!='frontend':configs[role]=mount['Name']
    configs['migrate']=LIVE+'_migrate-config'
    for name in configs.values():need(json.loads(run('docker','volume','inspect',name))[0]['Name']==name,'LIVE_CONFIG_VOLUME_MISSING')
    ingress=inventory['ingress'];core=LIVE+'_core';edges=[n for n in ingress['networks'] if n!=core];need(len(edges)==1,'INGRESS_EDGE_NETWORK')
    private=OUT/'live-inputs';private.mkdir(exist_ok=True);public=private/'public';public.mkdir(exist_ok=True)
    # Public CA/CRL material only. No fixture configuration or owner signing key.
    internal=ROOT/'target/full-function-20261111b/private/ca-with-crl.pem';browser=ROOT/'target/full-function-20261111b/windows-access/browser-tls-candidate/public'
    (public/'internal-ca-with-crl.pem').write_bytes(internal.read_bytes());(public/'browser-root.crt').write_bytes((browser/'browser-root.crt').read_bytes());(public/'all-ca-with-crl.pem').write_bytes(internal.read_bytes()+b'\n'+(browser/'browser-ca-with-crl.pem').read_bytes())
    runid=uuid.uuid4().hex[:16]
    plan={'version':1,'purpose':'D10_SINGLE_CONTROLLED_CUTOVER','project':LIVE,'run_id':runid,'approval_nonce':secrets.token_hex(24),'output':'target/full-function-20261111b/d10-phase3/'+runid,'source':source,'configuration_hashes':pre['configuration_hashes'],'config_volumes':configs,'source_volumes':list(configs.values())+[LIVE+'_redis-data'],'core_network':core,'maintenance_network':edges[0],'ingress_core_ip':ingress['networks'][core]['IPAddress'],'candidate_images':bound['images'],'utility_image':'redis@sha256:ec1c2d3603c3d7d65b153bedda0248b641aa3bd7684503406b27b9e870ac0796','tooling_image':run('docker','image','inspect','--format','{{.Id}}','zt-full-function/browser:20261111-1').decode().strip(),'pending_count':len(pre['existing_pending']),'trust_rows':pre['trust_rows'],'rehearsal_status':'PASS','executor_files':bound['executor_files'],'packet_sha256':sha((HERE/'binding.phase3.json').read_bytes()),'public_material':public.relative_to(ROOT).as_posix(),'new_designated_accounts':2,'new_school_rows':6,'post_acceptance_designated_accounts':'disable; never reset existing accounts','pending_policy':'preserve/quarantine exact existing two subjects and all four incomplete audit rows','deployment_authorized':False}
    plan['migrate_configuration_hashes']=pre['migrate_configuration_hashes']
    write(PLAN,plan);write(HERE/'owner-go.PENDING.json',{'type':'D10_OWNER_GO_PENDING','plan_sha256':sha(canonical(plan)),'nonce':plan['approval_nonce'],'owner_message_sha256':None,'deployment_authorized':False})
    print('READY packet '+sha(canonical(plan))+'; explicit owner GO absent; no live mutation')
def execute(approval):
    import packet,preflight
    packet.validate();plan=json.loads(PLAN.read_text());need(sha((HERE/'binding.phase3.json').read_bytes())==plan['packet_sha256'],'PACKET_DRIFT')
    # Constructor validates explicit owner scope BEFORE any helper/account/maintenance mutation.
    e=Executor(plan,'live',approval)
    preflight.main('live-execution-readonly.json')
    results=e.out;public=ROOT/plan['public_material'];private=results/'new-inputs.dpapi'
    with e.exclusive():
        try:
            need(e.j['phase']=='PREPARED','EXECUTION_ALREADY_STARTED_REVIEW_DURABLE_JOURNAL_NO_AUTOMATIC_REPLAY')
            e.assert_source();values=generated_inputs(e.id);values['provisioner_secret']=provisioner_secret(e);protect_inputs(private,values,e.id)
            container=helper(e,public,results);designated(e,container,values);protect_inputs(private,values,e.id)
            process=native_process(e,container,values,results,True);deadline=time.monotonic()+150
            while not (results/'legacy-witness.json').exists():need(process.poll()is None and time.monotonic()<deadline,'LEGACY_WITNESS_NOT_READY');time.sleep(.3)
            stage_install(e,container,values);monitor(e,container,process,results);report=verify_state(e,values,results)
            disabled=rpc(container,{**values,'action':'disable-designated'});write(results/'designated-cleanup.json',disabled)
            deadline=time.monotonic()+60
            while e.sql('SELECT COUNT(*) FROM pd_staging_risk.subject_device_trust WHERE pending_operation_id IS NOT NULL')!=str(plan['pending_count']):need(time.monotonic()<deadline,'DESIGNATED_DISABLE_PENDING');time.sleep(.5)
            e.assert_trust_preserved();cleanup=rpc(container,{**values,'action':'cleanup'});write(results/'temporary-admin-cleanup.json',cleanup)
            receipt={'status':'PASS','plan_sha256':e.hash,'images':plan['candidate_images'],**{key:True for key in ('strict_api','strict_issuer','legacy_denied','mfa_proof','reset_resume','rbac_ownership','tls_roles','B0_SHADOW','pending_preserved','performance')}}
            e.mark_acceptance(receipt);e.open_public()
            active={role:projection(e.j['created'][role] if role in ('risk','keycloak','backend','gateway','frontend') else e.name('public-ingress') if role=='ingress' else e.old[role]) for role in plan['source']}
            write(results/'active-runtime.json',{'status':'PASS','project':LIVE,'schema':9,'runtime':active,'mode':'SHADOW','live_risk_policy':'B0','retention':False,'D10':'PASS','D17':'PENDING','G8':'INTERNET_NO_GO','public_calibration':'PENDING','owner_go_plan':e.hash})
            e.stop(container);print('PASS controlled D10 cutover and mandatory native acceptance; strict-only human traffic reopened; security state retained')
        except Exception as error:e.hold(type(error).__name__);raise
def hold(approval):
    import packet
    packet.validate();plan=json.loads(PLAN.read_text());e=Executor(plan,'live',approval)
    with e.exclusive():e.hold('OWNER_AUTHORIZED_STRICT_RECOVERY_HOLD')
    print('HOLD_FAIL_CLOSED; inspect journal and native receipts; no automatic replay, old V7 start, security restore or human reopen')

def status():
    plan=json.loads(PLAN.read_text()) if PLAN.exists() else None
    journal=ROOT/plan['output']/'journal.json' if plan else None
    state=json.loads(journal.read_text()) if journal and journal.exists() else {}
    print(json.dumps({'this_read_only_action_grants_authorization':False,'plan_prepared':plan is not None,'plan_sha256':sha(canonical(plan)) if plan else None,'phase':state.get('phase','NOT_EXECUTED'),'recovery':'keep maintenance; review durable stages and positive native receipts; never replay UNKNOWN blindly','D10':'UNRESOLVED_UNTIL_DEPLOYED_ACCEPTANCE','D17':'PENDING','G8':'INTERNET_NO_GO'}))
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('prepare','status','execute','hold'),default='status',nargs='?');parser.add_argument('--go');args=parser.parse_args()
    try:
        if args.action in ('execute','hold'):need(args.go is not None,'EXPLICIT_OWNER_GO_REQUIRED');globals()[args.action](args.go)
        else:globals()[args.action]()
    except Exception as error:print('FAIL '+(str(error) if isinstance(error,RuntimeError) else type(error).__name__),file=sys.stderr);sys.exit(1)
