"""TEST-ONLY in-memory signers; no owner keys, anchor, signature files or grant.

Active mutator admission is tested with mocked Docker only. Real active access is
performed separately by READ-ONLY preflight. Actual mutations use disposable.
"""
import base64
import copy
import time
import unittest
from unittest import mock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import promotion_context as c
import promotion_executor as x
import risk_promotion as r


class OwnerBindingTests(unittest.TestCase):
    def setUp(self):
        self.m=r.json_bytes(c.DESCRIPTOR.read_bytes());self.digest=r.sha_file(c.DESCRIPTOR);self.packet=r.sha_file(c.PACKET)
        self.TEST_SIGNER=Ed25519PrivateKey.generate();pub=self.TEST_SIGNER.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        self.anchor={'kind':'OWNER_CONTROLLED_ACTIVE_ONLY','project':r.PROJECT,'owner_sid':self.m['owner_sid'],
            'issuer':'OWNER_EXPLICIT_ACTIVE_AUTHORIZATION','descriptor_sha256':self.digest,'packet_sha256':self.packet,
            'expires':int(time.time())+600,'operations':list(c.OPERATIONS),'public_key':base64.b64encode(pub).decode(),'public_key_sha256':r.sha(pub)}
        now=int(time.time())
        self.p={'id':'a'*32,'project':r.PROJECT,'operation':'backup-only','descriptor_sha256':self.digest,'packet_sha256':self.packet,
            'old_image':r.OLD,'new_image':r.NEW,'config_sha256':r.sha(c.canonical(self.m['proposed'])),
            'dataset_sha256':r.sha(c.canonical(self.m['geoip'])),'policy_sha256':r.sha(c.canonical(self.m['policy'])),
            'maintenance':list(x.WRITERS),'checkpoint':None,'checkpoint_rules_sha256':r.sha(c.canonical(self.m['checkpoint_rules'])),
            'rollback':r.OLD,'issued':now,'expires':now+300,'issuer':'OWNER_EXPLICIT_ACTIVE_AUTHORIZATION',
            'owner_sid':self.m['owner_sid'],'recover_of':None,'recover_target':None}
    def envelope(self):return {'payload':self.p,'signature':base64.b64encode(self.TEST_SIGNER.sign(c.canonical(self.p))).decode()}
    def check(self,used=(),operation='backup-only',envelope=None):
        return c.verify_owner_request(envelope or self.envelope(),self.m,self.digest,self.packet,operation,set(used),self.anchor)
    def reject(self,field,value,code):
        self.p[field]=value
        with self.assertRaisesRegex(r.Rejected,code):self.check()
    def test_valid_in_memory_fixture_only(self):self.assertEqual(self.check()['operation'],'backup-only')
    def test_wrong_project(self):self.reject('project',x.LANE,'PROJECT_MISMATCH')
    def test_stale_descriptor(self):self.reject('descriptor_sha256','0'*64,'BINDING_MISMATCH')
    def test_wrong_packet(self):self.reject('packet_sha256','0'*64,'BINDING_MISMATCH')
    def test_expired_request(self):self.reject('expires',int(time.time())-1,'REQUEST_STALE')
    def test_replay(self):
        with self.assertRaisesRegex(r.Rejected,'ALREADY_USED'):self.check(used=[self.p['id']])
    def test_wrong_operation(self):self.reject('operation','apply','BINDING_MISMATCH')
    def test_wrong_image(self):self.reject('new_image',r.OLD,'BINDING_MISMATCH')
    def test_wrong_policy(self):self.reject('policy_sha256','0'*64,'BINDING_MISMATCH')
    def test_wrong_dataset(self):self.reject('dataset_sha256','0'*64,'BINDING_MISMATCH')
    def test_wrong_configuration(self):self.reject('config_sha256','0'*64,'BINDING_MISMATCH')
    def test_maintenance_scope(self):self.reject('maintenance',['mysql'],'BINDING_MISMATCH')
    def test_checkpoint_rules(self):self.reject('checkpoint_rules_sha256','0'*64,'BINDING_MISMATCH')
    def test_anchor_reviewed_digest(self):
        self.anchor['descriptor_sha256']='0'*64
        with self.assertRaisesRegex(r.Rejected,'REVIEWED_DIGEST'):self.check()
    def test_signer_mismatch(self):
        env=self.envelope();env['signature']=base64.b64encode(Ed25519PrivateKey.generate().sign(c.canonical(self.p))).decode()
        with self.assertRaisesRegex(r.Rejected,'SIGNATURE_INVALID'):self.check(envelope=env)
    def test_harness_issuer_cannot_claim_owner(self):self.reject('issuer','TEST_HARNESS_CURRENT_USER_REHEARSAL_ONLY','BINDING_MISMATCH')
    def test_unknown_field_not_force(self):self.reject('force',True,'REQUEST_SHAPE')
    def test_integer_operation_id(self):self.reject('id',12345678901234567890123456789012,'OPERATION_ID')
    def test_apply_requires_checkpoint(self):
        self.p['operation']='apply'
        with self.assertRaisesRegex(r.Rejected,'CHECKPOINT_REQUIRED'):self.check(operation='apply')
    def test_restore_references_exact_checkpoint(self):
        self.p.update(operation='restore-verify',checkpoint='b'*32)
        self.assertEqual(self.check(operation='restore-verify')['checkpoint'],'b'*32)
    def test_no_scope_expansion_by_anchor(self):
        self.anchor['operations']=['backup-only']
        with self.assertRaisesRegex(r.Rejected,'OPERATION_NOT_AUTHORIZED'):self.check(operation='apply')


class ContextIsolationTests(unittest.TestCase):
    def setUp(self):
        with mock.patch.object(r.ReadOnlyDocker,'local'):
            self.a=c.Context('active');self.d=c.Context('disposable')
    def test_namespaces_private_keys_locks_and_core_are_separate(self):
        self.assertIsNot(self.a.module,self.d.module)
        self.assertNotEqual(self.a.module.PRIVATE,self.d.module.PRIVATE)
        self.assertNotEqual(self.a.module.CORE,self.d.module.CORE)
        self.assertEqual(x.LANE,'zt-full-function-phase2-restore')
    def test_wrong_context_name_not_a_project_switch(self):
        with self.assertRaisesRegex(r.Rejected,'UNKNOWN_EXECUTION_CONTEXT'):c.Context(r.PROJECT)
    def test_missing_active_approval_before_any_docker_or_private_creation(self):
        self.a.engine.d=mock.Mock()
        with self.assertRaisesRegex(r.Rejected,'EXPLICIT_OPERATION_AUTHORIZATION_REQUIRED'):self.a.engine.backup(None)
        self.a.engine.d.raw.assert_not_called();self.assertFalse(c.ACTIVE_PRIVATE.exists())
    def test_disposable_request_cannot_authorize_active(self):
        # A fake envelope is not written to any production anchor/request path.
        self.a.engine.d=mock.Mock()
        with mock.patch.object(c,'load_owner_anchor',side_effect=r.Rejected('OWNER_TRUST_ANCHOR_NOT_ENROLLED')):
            with self.assertRaisesRegex(r.Rejected,'TRUST_ANCHOR_NOT_ENROLLED'):self.a.engine.restart({'payload':{'project':x.LANE},'signature':'TEST'})
        self.a.engine.d.raw.assert_not_called()
    def test_direct_docker_mutation_without_grant_rejected(self):
        with self.assertRaisesRegex(r.Rejected,'MUTATION_WITHOUT'):self.a.engine.d.raw('docker','stop',r.PROJECT+'-risk-1')
    def test_operation_capability_does_not_leak_to_other_thread(self):
        import threading
        failures=[];token=self.a._capability.set({'active':True,'project':r.PROJECT})
        def other():
            try:self.a.require_capability()
            except r.Rejected:failures.append('REJECTED')
        try:
            t=threading.Thread(target=other);t.start();t.join();self.a.require_capability()
            self.assertEqual(failures,['REJECTED'])
        finally:self.a._capability.reset(token)
    def test_no_arbitrary_exec_disguised_as_health(self):
        self.assertFalse(c.Context.read_command(('docker','exec','name','java','-cp','evil','Health','https://risk:8443/actuator/health','200')))
    def test_select_into_is_not_a_read_only_command(self):
        self.assertFalse(c.Context.read_command(('docker','exec','name','mysql','-e',"SELECT 1 INTO OUTFILE '/tmp/x'")))
    def test_changed_container_rejected(self):
        s=self.a.m['services']['risk'];row={'Id':'foreign','Image':r.OLD,'Config':{'Labels':{'io.zerotrust.scope':r.PROJECT}},'HostConfig':{'PortBindings':{}}}
        with mock.patch.object(self.a.engine.d,'inspect',return_value=row):
            with self.assertRaisesRegex(r.Rejected,'CONTAINER_ID_DRIFT'):self.a.engine.d.owned(s['name'])
    def test_changed_image_rejected(self):
        s=self.a.m['services']['risk'];row={'Id':s['id'],'Image':r.NEW,'Config':{'Labels':{'io.zerotrust.scope':r.PROJECT}},'HostConfig':{'PortBindings':{}}}
        with mock.patch.object(self.a.engine.d,'inspect',return_value=row):
            with self.assertRaisesRegex(r.Rejected,'IMAGE_DRIFT'):self.a.engine.d.owned(s['name'])
    def test_private_service_port_rejected(self):
        s=self.a.m['services']['risk'];row={'Id':s['id'],'Image':r.OLD,'Config':{'Labels':{'io.zerotrust.scope':r.PROJECT}},'HostConfig':{'PortBindings':{'8443/tcp':[{'HostIp':'0.0.0.0','HostPort':'4443'}]}}}
        with mock.patch.object(self.a.engine.d,'inspect',return_value=row):
            with self.assertRaisesRegex(r.Rejected,'PUBLISHED_PORT'):self.a.engine.d.owned(s['name'])
    def test_only_exact_reviewed_loopback_ingress_allowed(self):
        s=self.a.m['services']['ingress'];row={'Id':s['id'],'Image':s['witness']['image'],'Config':{'Labels':{'io.zerotrust.scope':r.PROJECT}},'HostConfig':{'PortBindings':s['witness']['ports']}}
        with mock.patch.object(self.a.engine.d,'inspect',return_value=row):self.assertEqual(self.a.engine.d.owned(s['name'])['Id'],s['id'])
    def test_renaming_project_in_descriptor_cannot_enable(self):
        self.a.m['project']=x.LANE
        with self.assertRaisesRegex(r.Rejected,'DESCRIPTOR_IDENTITY'):self.a.validate_descriptor()
    def test_boolean_cannot_enable_owner_authorization(self):
        self.a.m['authorization']['owner_signature_required']=False
        with self.assertRaisesRegex(r.Rejected,'NOT_AN_AUTHORIZATION'):self.a.validate_descriptor()
    def test_unknown_descriptor_field_rejected(self):
        self.a.m['execution_enabled']=True
        with self.assertRaisesRegex(r.Rejected,'DESCRIPTOR_SHAPE'):self.a.validate_descriptor()
    def test_checkpoint_freshness_unchanged(self):
        with mock.patch.object(self.d.module,'sealed_read',return_value={'project':x.LANE,'manifest':self.d.digest,'restore_verified':True,'created':0,'files':{}}):
            with self.assertRaisesRegex(r.Rejected,'NOT_VERIFIED_OR_STALE'):self.d.engine.load_checkpoint('a'*32,True)
    def test_legacy_guard_cannot_overwrite_initialized_active_context(self):
        import tempfile
        from pathlib import Path
        fixture=Path(tempfile.mkdtemp(prefix='legacy-guard-',dir=c.OUT))
        (fixture/(r.PREFIX+'promotion-private')).mkdir(parents=True)
        adapter=mock.Mock()
        with self.assertRaisesRegex(r.Rejected,'ACTIVE_CONTEXT_OWNS_OPERATIONS'):r.assert_legacy_runtime(root=fixture,adapter=adapter)
        adapter.local.assert_not_called()


if __name__=='__main__':unittest.main(verbosity=2)
