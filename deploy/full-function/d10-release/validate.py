"""Read-only D10 offline release verifier. Deliberately contains no apply/restart/rollback path."""
import hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
def need(ok,message):
    if not ok:raise RuntimeError(message)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def validate():
    b=json.loads((HERE/'binding.offline.json').read_text())
    need(b['purpose']=='D10_OFFLINE_RELEASE' and b['deployment_authorized'] is False,'NOT_AN_OFFLINE_BINDING')
    need(b['offline_status']=='PASS','OFFLINE_ACCEPTANCE_INCOMPLETE')
    for path,digest in b['files'].items():
        p=(ROOT/path).resolve();need(p.is_relative_to(ROOT) and p.is_file(),'FILE_SCOPE_OR_MISSING')
        need(sha(p)==digest,'BOUND_FILE_DRIFT_'+path)
    for role,artifact in b['images'].items():
        result=subprocess.run(['docker','image','inspect','--format','{{.Id}}',artifact['image']],capture_output=True,text=True,timeout=20)
        need(result.returncode==0 and result.stdout.strip()==artifact['id'],'IMAGE_DRIFT_'+role)
    evidence=json.loads((ROOT/b['verification']).read_text())
    need(evidence['offline_status']=='PASS' and evidence['native']['failures']==0,'EVIDENCE_NOT_PASS')
    need(evidence['preservation']['status']=='PASS','PRESERVATION_NOT_PASS')
    contract=json.loads((HERE/'contract.json').read_text())
    need(contract['network_risk']=={'live_policy':'B0','v2_mode':'SHADOW','retention_enabled':False},'SHADOW_CONTRACT_DRIFT')
    need(contract['authority']['positive_cache'] is False and contract['deployment_authorized'] is False,'UNSAFE_CONTRACT')
    need(all('d10-fixture' not in value for value in contract['tls'].values() if isinstance(value,str)),'FIXTURE_PROXY_IN_RELEASE')
    print('PASS D10 offline artifacts, source/evidence hashes and separate configuration contract; deployment NOT authorized')
if __name__=='__main__':
    try:validate()
    except Exception as error:
        print('FAIL '+(str(error) if type(error)is RuntimeError else type(error).__name__),file=sys.stderr);sys.exit(1)
