"""D10 Phase3 reviewed packet; Phase2 server evidence is reused, never relabelled as new tests."""
import json,subprocess,sys
from pathlib import Path
from executor import ROOT,need,run,sha,write
HERE=Path(__file__).resolve().parent;OUT=ROOT/'target/d10-phase3-20261113'
CALLBACK_FILES=('frontend/components/admin-catalogs.tsx','frontend/lib/keycloak.ts')
def verify_base():
    base=json.loads((HERE/'binding.offline.json').read_text());changes={}
    for name,digest in base['files'].items():
        actual=sha((ROOT/name).read_bytes())
        if actual!=digest:
            need(name in CALLBACK_FILES,'UNREVIEWED_PHASE2_DRIFT_'+name);changes[name]={'before':digest,'after':actual}
    need(set(changes)==set(CALLBACK_FILES),'CALLBACK_FIX_SCOPE_CHANGED')
    front=json.loads((OUT/'frontend-artifact.json').read_text())
    need(run('docker','image','inspect','--format','{{.Id}}',front['image']).decode().strip()==front['id'],'NEW_FRONTEND_IMAGE_DRIFT')
    for name in CALLBACK_FILES:need(sha((OUT/'frontend-build'/name).read_bytes())==changes[name]['after'],'FRONTEND_BUILD_SOURCE_DRIFT')
    images={r:a['id'] for r,a in base['images'].items()};images['frontend']=front['id']
    for role,image in images.items():need(run('docker','image','inspect','--format','{{.Id}}',image).decode().strip()==image,'CANDIDATE_IMAGE_MISSING_'+role)
    return base,images,changes
def seal():
    base,images,changes=verify_base();proof=json.loads((OUT/'rehearsal-final2/REHEARSAL.json').read_text());need(proof['status']=='PASS','FINAL_REHEARSAL_NOT_PASS')
    pre=json.loads((OUT/'live-preflight.json').read_text());need(pre['schema']==7 and pre['owner_go']is False,'LIVE_BASELINE')
    code={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in HERE.glob('*.py')}
    evidence={name:sha((ROOT/name).read_bytes()) for name in ('target/d10-phase3-20261113/rehearsal-final2/REHEARSAL.json','target/d10-phase3-20261113/rehearsal-final2/rollout-native.json','target/d10-phase3-20261113/live-preflight.json','target/d10-phase3-20261113/frontend-artifact.json','target/d10-phase3-20261113/frontend-build.log','target/d10-phase3-executor-tests.log','target/d10-phase3-20261113/preservation-after.json','target/d10-phase3-20261113/maintenance-proof.json','target/d10-phase3-20261113/helper-smoke.json')}
    binding={'purpose':'D10_PHASE3_CONTROLLED_ROLLOUT','version':1,'owner_go':False,'base_binding_sha256':sha((HERE/'binding.offline.json').read_bytes()),'base_tests':'457 Java reused +12 frontend rerun; 18 unchanged native server cases reused','images':images,'source_changes':changes,'executor_files':code,'evidence':evidence,'rehearsal':'PASS','new_callback':'https://portal.full-function.test:39443/admin/users','reserved_attributes':'native unmanaged policy null (disabled); no reserved managed attributes','existing_pending_policy':'preserve exact 2 V7 pending subjects/generations/operation IDs and 4 incomplete audit rows; quarantine, no clear/supersede','rollback':'strict-compatible repair only; no old V7 human traffic or security-state restore'}
    write(HERE/'binding.phase3.json',binding);print('PASS Phase3 packet sealed: four unchanged server pins, callback-fixed frontend, reviewed executor and native rehearsal; owner GO absent')
def validate():
    _,images,changes=verify_base();binding=json.loads((HERE/'binding.phase3.json').read_text());need(binding['images']==images and binding['source_changes']==changes,'PHASE3_RELEASE_DRIFT')
    for name,digest in {**binding['executor_files'],**binding['evidence']}.items():need(sha((ROOT/name).read_bytes())==digest,'PHASE3_BOUND_FILE_DRIFT_'+name)
    print('PASS exact Phase3 images/code/evidence; no deployment authorization')
if __name__=='__main__':
    try:
        action=sys.argv[1] if len(sys.argv)>1 else 'validate';need(action in ('base','seal','validate'),'READ_ONLY_PACKET_ACTION')
        if action=='base':verify_base();print('PASS unchanged Phase2 server/source evidence and narrowly scoped frontend callback fix')
        else:globals()[action]()
    except Exception as e:print('FAIL '+(str(e) if isinstance(e,RuntimeError) else type(e).__name__),file=sys.stderr);sys.exit(1)
