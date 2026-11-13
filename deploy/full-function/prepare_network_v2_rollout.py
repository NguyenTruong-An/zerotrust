"""Prepare corrected v3 binding from the closed v2 incident. Public offline metadata only."""
import json
import network_v2_rollout as n
import network_v2_contract as c
import promotion_executor as x

def main():
    n.need(not n.DESCRIPTOR.exists() and not n.PACKET.exists(),'SHADOW_PACKAGE_EXISTS_DO_NOT_OVERWRITE')
    n.need(n.r.sha_file(n.PARENT_DESCRIPTOR)==n.PARENT_SHA and n.r.sha_file(n.PARENT_PACKET)==n.PARENT_PACKET_SHA,'SHADOW_PARENT_DRIFT')
    m=n.r.json_bytes(n.PARENT_DESCRIPTOR.read_bytes());p=n.r.json_bytes(n.PARENT_PACKET.read_bytes())
    before_path=n.OUT/'cutover-v3-before.json';before=n.r.json_bytes(before_path.read_bytes())
    emergency_path=n.OUT/'emergency-6fc9ee61/post-recovery-acceptance.json';emergency=n.r.json_bytes(emergency_path.read_bytes())
    n.need(before['status']=='PASS' and before['schema']==7 and not before['unfinished']
           and emergency['status']=='PASS' and not emergency['data_differences'],'SHADOW_V7_RECOVERY_CLOSURE_REQUIRED')
    tests_path=n.OUT/'cutover-v3-tests.json';tests=n.r.json_bytes(tests_path.read_bytes())
    n.need(tests['status']=='PASS' and all(n.r.sha_file(n.HERE/name)==digest for name,digest in tests['source_sha256'].items()),'SHADOW_TESTED_V3_CODE_DRIFT')
    m['binding_revision']=3
    m['predecessors']={n.PREVIOUS_SHA:m.pop('predecessor'),n.PARENT_SHA:{'packet_sha256':n.PARENT_PACKET_SHA,'control_files_sha256':before['parent_private_files']}}
    n.predecessor_guard(m)
    docker=n.r.ReadOnlyDocker();docker.local()
    baseline=n.r.json_bytes(docker.command('docker','inspect',*[m['services'][role]['name'] for role in n.NEW]))
    images=n.r.json_bytes(docker.command('docker','image','inspect',*n.NEW.values()))
    for row in baseline:
        role=next(role for role in n.NEW if m['services'][role]['id']==row['Id'])
        n.need(x.public_witness(row)==m['services'][role]['witness'] and row['State']['Running'],'SHADOW_BASELINE_RUNTIME_DRIFT')
    specs={role:c.expected_spec(role,next(row for row in baseline if row['Id']==m['services'][role]['id']),next(image for image in images if image['Id']==n.NEW[role]),m,n.PROJECT,n.CORE) for role in n.NEW}
    m['release'].pop('risk_environment_sha256',None)
    m['release'].update(initial_schema=7,migration_mode='VALIDATE_V7_NO_DDL',environment_hash_algorithm='STRICT_JSON_CANONICAL_ENV_V1',
        candidate_contracts={role:spec['contract'] for role,spec in specs.items()},
        schema_policy='Exact V7 checksums required; no Flyway execution or DDL; CURRENT storage retained',
        pre_cutover_policy='Canonical offline preflight, stage both dormant containers, inspect complete actual contracts, then quiesce; rejected dormant candidates retained with terminal rejection journal')
    m['implementation_sha256']={name:n.r.sha_file(n.HERE/name) for name in ('network_v2_rollout.py','network_v2_contract.py','network_v2_postcheck.py','owner_shadow_authorize.py','prepare_network_v2_rollout.py')}
    history=n.PACKAGE/'history'/n.PARENT_SHA
    for path in [before_path,emergency_path,tests_path,*sorted(history.iterdir())]:
        m['receipts'].append({'path':str(path.relative_to(n.r.ROOT)).replace('\\','/'),'sha256':n.r.sha_file(path)})
    n.DESCRIPTOR.write_bytes(n.canonical(m)+b'\n')
    p.update(binding_revision=3,descriptor_sha256=n.r.sha_file(n.DESCRIPTOR),release=m['release'],
        new_private_root=str(n.PRIVATE.relative_to(n.r.ROOT)).replace('\\','/'),owner_anchor=str(n.ANCHOR),
        previous_descriptor_sha256=n.PARENT_SHA,previous_packet_sha256=n.PARENT_PACKET_SHA,
        preflight='Exact canonical environment and full Risk/KC contract; actual dormant Docker inspection BEFORE any writer stop or migration',
        schema='Existing V7 validated no-op; no DDL, restore, downgrade or cleanup',
        failure='Before-cutover mismatch: no stop/DDL/swap, reject journal and retain only dormant owned candidates. After mutation: ingress closed, HMAC recovery journal preserved.')
    n.PACKET.write_bytes(n.canonical(p)+b'\n');n.descriptor()
    print(json.dumps({'status':'PREPARED_NOT_AUTHORIZED','descriptor_sha256':n.r.sha_file(n.DESCRIPTOR),'packet_sha256':n.r.sha_file(n.PACKET),'controller_sha256':m['implementation_sha256']['network_v2_rollout.py'],'new_private_created':n.PRIVATE.exists(),'new_anchor_created':n.ANCHOR.exists()}))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'REJECTED','code':str(error) if isinstance(error,n.r.Rejected) else type(error).__name__}));raise SystemExit(1)
