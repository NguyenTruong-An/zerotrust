"""One incident, BASELINE-only signed recovery extension. Pinned v2 code is untouched.

The normal one-use recovery signature AND a second signature over this exact
extension descriptor/request are mandatory. A stopped candidate is validated
against its exactly reproduced creator environment, never started or modified.
"""
import argparse
import base64
import copy
import json
from pathlib import Path
import sys
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import network_v2_rollout as n

OP='6fc9ee6138264eeb9223568c01a1194c'
DESCRIPTOR=n.PACKAGE/'emergency-recover-6fc9ee61.json'
OUT=n.OUT/'emergency-6fc9ee61'
KIND='EXACT_STOPPED_CANDIDATE_BASELINE_RECOVERY_EXTENSION_V1'


def descriptor():
    value=n.r.json_bytes(DESCRIPTOR.read_bytes())
    n.need(value['kind']==KIND and value['project']==n.PROJECT
           and value['recover_of']==OP and value['target']=='BASELINE'
           and value['baseline_images']==n.OLD and value['schema']==7,
           'EMERGENCY_SCOPE')
    n.need(value['parent_descriptor_sha256']==n.r.sha_file(n.DESCRIPTOR)
           and value['parent_packet_sha256']==n.r.sha_file(n.PACKET),'EMERGENCY_PARENT_BINDING')
    n.need(value['start_candidates'] is False and value['database_restore'] is False
           and value['migration'] is False,'EMERGENCY_FORBIDDEN_OPERATION')
    for name,digest in value['implementation_sha256'].items():
        n.need(n.r.sha_file(n.HERE/name)==digest,'EMERGENCY_IMPLEMENTATION_DRIFT')
    for row in value['receipts']:
        n.need(n.r.sha_file(n.r.local_path(n.r.ROOT,row['path']))==row['sha256'],'EMERGENCY_EVIDENCE_DRIFT')
    n.descriptor()  # Every original source/receipt/owner/project binding stays enforced.
    return value


def extension_payload(core,em,now=None):
    return {'kind':KIND,'request_sha256':n.sha(n.canonical(core)),
            'emergency_descriptor_sha256':n.r.sha_file(DESCRIPTOR),
            'parent_descriptor_sha256':em['parent_descriptor_sha256'],
            'recover_of':OP,'target':'BASELINE','baseline_images':n.OLD,'schema':7,
            'quarantine_witness_sha256':n.sha(n.canonical(em['quarantine'])),
            'issued':core['payload']['issued'],'expires':core['payload']['expires']}


def verify_extension(extension,core,em,anchor,now=None):
    now=int(time.time()) if now is None else now
    n.need(type(extension) is dict and set(extension)=={'payload','signature'},'EMERGENCY_EXTENSION_SHAPE')
    expected=extension_payload(core,em)
    n.need(extension['payload']==expected,'EMERGENCY_EXTENSION_BINDING')
    n.need(expected['issued']<=now+5 and now<expected['expires']<=expected['issued']+600,'EMERGENCY_EXTENSION_EXPIRED')
    try:
        public=base64.b64decode(anchor['public_key'],validate=True)
        n.need(n.sha(public)==anchor['public_key_sha256'],'EMERGENCY_PUBLIC_KEY_HASH')
        Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(extension['signature'],validate=True),n.canonical(expected))
    except Exception:raise n.r.Rejected('EMERGENCY_EXTENSION_SIGNATURE_INVALID') from None


def stopped_candidate_guard(ctx,row,record):
    """No generic hash exemption: same ID + full contract + exact creator Env."""
    n.need(row['Id']==record['id'] and row['Name']=='/'+record['name']
           and not row['State']['Running'] and not row['State'].get('Paused')
           and row['State']['Status']=='created','EMERGENCY_CANDIDATE_NOT_EXACT_STOPPED_CREATED')
    n.need(ctx.module.public_witness(row)==record['witness'],'EMERGENCY_QUARANTINE_CONTRACT_DRIFT')
    baseline=ctx.executor.d.owned(ctx.m['services']['risk']['name'])
    expected=[v for v in baseline['Config']['Env'] if not v.startswith('SPRING_APPLICATION_JSON=')]
    expected+=['SPRING_APPLICATION_JSON='+json.dumps(ctx.m['release']['risk_override'])]
    actual=row['Config']['Env']
    n.need(len({v.split('=',1)[0] for v in actual})==len(actual)
           and sorted(actual)==sorted(expected),'EMERGENCY_CREATOR_ENV_NOT_REPRODUCIBLE')
    observed=n.sha(json.dumps(sorted(actual)).encode())
    n.need(observed==record['reproduced_environment_sha256'],'EMERGENCY_EXACT_ENV_HASH_DRIFT')
    # Original validator executes ALL provenance/ID/image/network/mount/hardening/
    # override/entrypoint/command checks; only this signed stopped-row Env digest
    # is corrected on a disposable proxy, never the real descriptor/context.
    proxy=object.__new__(n.Context);proxy.__dict__=dict(ctx.__dict__)
    proxy.m={**ctx.m,'release':{**ctx.m['release'],'risk_environment_sha256':observed}}
    n.Context.verify_replacement(proxy,row,OP)


class EmergencyContext(n.Context):
    def __init__(self,extension=None):
        self.em=descriptor();self.extension=extension
        super().__init__()
    def incident_guard(self):
        e=self.executor;target=self.module.sealed_read(e.journal(OP))
        n.need(n.r.sha_file(e.journal(OP))==self.em['target_journal_sha256']
               and target['operation']=='apply' and target['status']=='RUNNING'
               and target['manifest']==self.digest,'EMERGENCY_INCIDENT_JOURNAL_CHANGED')
        n.need(e.state()==self.em['before_state'],'EMERGENCY_SELECTION_CHANGED')
        rows=e.d.rows()
        for role in ('risk','keycloak'):
            n.need(not any(row['State']['Running'] and n.CORE in row['NetworkSettings']['Networks']
                           and (role in (row['NetworkSettings']['Networks'][n.CORE].get('Aliases') or [])
                                or row['Image'] in (n.OLD[role],n.NEW[role])) for row in rows),
                   'EMERGENCY_UNEXPECTED_RUNNING_WRITER')
        for row in rows:
            if row['Name']=='/'+n.PROJECT+'-shadow-migrate-'+OP[:12]:
                self.verify_migrator(row);n.need(not row['State']['Running'] and row['State']['ExitCode']==0,
                                               'EMERGENCY_MIGRATOR_NOT_FINISHED')
        stopped_candidate_guard(self,e.d.inspect(self.em['quarantine']['name']),self.em['quarantine'])
        n.need(self.schema()==7,'EMERGENCY_SCHEMA_DRIFT')
        return target
    def verify_replacement(self,row,operation=None):
        if row['Id']==self.em['quarantine']['id']:
            n.need(operation in (None,OP),'EMERGENCY_WRONG_CANDIDATE_OPERATION')
            return stopped_candidate_guard(self,row,self.em['quarantine'])
        return super().verify_replacement(row,operation)
    def authorize(self,envelope,operation,used=None,now=None):
        n.need(operation=='recover' and envelope['payload']['recover_of']==OP
               and envelope['payload']['recover_target']=='BASELINE','EMERGENCY_ONLY_EXACT_BASELINE_RECOVERY')
        result=super().authorize(envelope,operation,used,now)
        self.em=descriptor()
        verify_extension(self.extension,envelope,self.em,n.r.json_bytes(n.ANCHOR.read_bytes()),now)
        self.incident_guard()  # Rechecked under the original shared project lock.
        return result
    def recover(self,j):
        self.require_grant()
        self.executor.stage(j,'EMERGENCY_RECOVERY_INTENT',emergency_descriptor_sha256=n.r.sha_file(DESCRIPTOR),
                            extension=self.extension,quarantine_container=self.em['quarantine']['id'])
        # Mark intent on THIS recovery journal before modifying target/services;
        # a partial failure cannot be mislabelled REJECTED_BEFORE_ACTIVE_MUTATION.
        return super().recover(j)
    def preflight(self):
        self.incident_guard();result=self.validate(False)
        n.need(result['mode']=='BASELINE' and result['schema']==7
               and result['unfinished']==[OP],'EMERGENCY_PENDING_SET_CHANGED')
        current=self.executor.table_witness()
        n.need(current==self.em['data_before'],'EMERGENCY_PROTECTED_DATA_DRIFT')
        return {'status':'READY_FOR_OWNER_SIGNATURE','recover_of':OP,'target':'BASELINE','schema':7,
                'emergency_descriptor_sha256':n.r.sha_file(DESCRIPTOR),'parent_descriptor_sha256':self.digest,
                'candidate_kept_stopped':True,'no_mutation':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('plan','execute'),nargs='?',default='plan')
    parser.add_argument('--request',type=Path);args=parser.parse_args()
    if args.action=='plan':result=EmergencyContext().preflight()
    else:
        n.need(args.request is not None,'EMERGENCY_SIGNED_REQUEST_REQUIRED')
        # Fixed owner root and owner ACL; no arbitrary public/untrusted request file.
        n.need(args.request.parent==n.ANCHOR.parent/'requests','EMERGENCY_REQUEST_OWNER_PATH')
        n.legacy.owner_acl(args.request)
        bundle=n.r.json_bytes(args.request.read_bytes())
        n.need(set(bundle)=={'request','extension'},'EMERGENCY_BUNDLE_SHAPE')
        ctx=EmergencyContext(bundle['extension']);ctx.preflight()
        ctx.execute(bundle['request'],'recover')
        result=n.Context().validate(True)
        n.need(result['status']=='PASS' and result['mode']=='BASELINE' and result['schema']==7
               and not result['unfinished'],'EMERGENCY_POSTCHECK_FAILED')
        OUT.mkdir(exist_ok=True)
        (OUT/'recovery-result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'REJECTED','code':str(error) if isinstance(error,n.r.Rejected) else type(error).__name__}));raise SystemExit(1)
