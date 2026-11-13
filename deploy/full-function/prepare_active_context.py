"""OFFLINE/read-only binding preparation; never emits owner keys or approvals.

Refuses to regenerate when an active private root or owner anchor is present.
Historical v1 proposal/packet/receipts are not changed.
"""
import json
import promotion_context as c
import promotion_executor as x
import risk_promotion as r


def prepare():
    r.need(not c.ACTIVE_PRIVATE.exists() and not c.OWNER_ANCHOR.exists(),'REVIEWED_ACTIVE_CONTEXT_ALREADY_ENROLLED_NO_REGENERATION')
    v=r.json_bytes(r.DEFAULT_MANIFEST.read_bytes());r.need(r.sha_file(r.DEFAULT_MANIFEST)==c.BASE_PROPOSAL_SHA,'ORIGINAL_PROPOSAL_DRIFT')
    d=x.Docker()
    # Inspect only the nine immutable baseline IDs, avoiding a race with --rm
    # disposable helper containers that are intentionally short lived.
    rows={z['Id']:z for z in r.json_bytes(d.raw('docker','inspect',*[z['id'] for z in v['baseline_runtime'].values()]))}
    services={}
    for service,witness in v['baseline_runtime'].items():
        expected=dict(witness)
        for k in ('entrypoint','cmd'):expected[k+'_sha256']=r.sha(c.canonical(expected.pop(k)))
        actual=x.public_witness(rows[witness['id']]);r.need(actual==expected,'ACTIVE_BASELINE_WITNESS_DRIFT')
        services[service]={'name':rows[witness['id']]['Name'].lstrip('/'),'id':witness['id'],'witness':actual}
    m={'version':1,'kind':c.ACTIVE_KIND,'project':r.PROJECT,'authority_sha256':c.TASK_SHA,
       'active_proposal_sha256':r.sha_file(r.DEFAULT_MANIFEST),'review_HEAD':r.ReadOnlyDocker().head(),'services':services,
       'volumes':sorted({z['Name'] for s in v['baseline_runtime'].values() for z in s['mounts']}),'networks':v['networks'],
       'config':{'app_sha256':v['config']['application_sha256'],'jvm_sha256':v['config']['jvm_sha256'],'defaults':v['config']['artifact_defaults']},
       'policy':v['policy'],'geoip':v['geoip'],'tls':v['tls'],
       'proposed':{'image':r.NEW,'application':r.GEO,'security':v['override']['security'],'rollback':r.OLD},'receipts':v['receipts'],
       'D17':'PENDING','G8':'INTERNET_NO_GO','approval_status':'PENDING','owner_sid':c.current_sid(),
       'private_root':str(c.ACTIVE_PRIVATE.relative_to(r.ROOT)).replace('\\','/'),'owner_anchor':str(c.OWNER_ANCHOR).replace('\\','/'),
       'checkpoint_rules':{'maximum_age_seconds':1800,'independent_restore_required':True,'automatic_database_restore':False},
       'authorization':{'owner_signature_required':True,'issuer':'OWNER_EXPLICIT_ACTIVE_AUTHORIZATION','maximum_request_seconds':600},
       'implementation_sha256':{p:r.sha_file(r.HERE/p) for p in c.CODE_FILES}}
    x.jwrite(c.DESCRIPTOR,m)
    packet={'version':2,'kind':'PENDING_ACTIVE_CUTOVER_REVIEW_NOT_AUTHORIZATION','project':r.PROJECT,'approval_status':'PENDING',
        'descriptor_path':c.DESCRIPTOR.name,'descriptor_sha256':r.sha_file(c.DESCRIPTOR),
        'old_packet_sha256':r.sha_file(r.HERE/'active-risk-cutover.PENDING.json'),
        'images':v['images'],'geoip':v['geoip'],'policy':v['policy'],'proposed_security':v['override']['security'],
        'maintenance':'exclusive active lock; ingress closed through internal validation and durable commit; restore running intent',
        'verification_scope':'ephemeral Risk-only history/evaluation; no account/credential/trust registration; browser/MFA evidence reused',
        'active_checkpoint':'NOT_CREATED','checkpoint_rules':m['checkpoint_rules'],
        'backup_scope':['School/Keycloak/Risk schemas','Redis AOF','8 config volumes','encrypted runtime/descriptor','GeoIP references'],
        'rollback':'exact OLD/config with CURRENT DB/Redis; no automatic data restore',
        'authorization':'externally anchored owner Ed25519 signature per operation; packet status never grants authorization',
        'next_owner_scope':['backup-only','restore-verify'],'no_active_mutation_this_phase':True,
        'residuals':['D10 unchanged','D17 PENDING','G8 INTERNET_NO_GO','public-browser GeoIP NOT_VERIFIED','daemon/Windows NOT_VERIFIED','signed image provenance NOT_VERIFIED'],
        'expected_interruption':'15-20 min maintenance window; 3-5 min rollback estimate from local rehearsal, not a Cloud promise',
        'D17':'PENDING','G8':'INTERNET_NO_GO'}
    x.jwrite(c.PACKET,packet)
    return {'descriptor_sha256':r.sha_file(c.DESCRIPTOR),'packet_sha256':r.sha_file(c.PACKET),'approval':'PENDING'}


if __name__=='__main__':print(json.dumps(prepare()))
