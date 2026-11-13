"""New executor authorization/journal tests; no Docker mutation or owner approval."""
import copy
import json
import os
import time
import unittest
from unittest import mock
import promotion_executor as x
import promotion_rehearsal as harness
import risk_promotion as r


class AuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e=x.Executor(docker=object())
    def setUp(self):self.envelope,_=harness.request(self.e,'apply',checkpoint='a'*32)
    def check(self,envelope=None,m=None,op='apply',used=()):
        return x.verify_request(envelope or self.envelope,m or self.e.m,self.e.digest,op,set(used))
    def resign(self):
        key=x.Ed25519PrivateKey.from_private_bytes((x.PRIVATE/'rehearsal-auth.key').read_bytes())
        self.envelope['signature']=x.base64.b64encode(key.sign(x.canonical(self.envelope['payload']))).decode()
    def test_valid_scoped_test_request(self):self.assertEqual(self.check()['project'],x.LANE)
    def test_protected_project_even_with_valid_test_signature(self):
        self.envelope['payload']['project']=r.PROJECT;self.resign()
        with self.assertRaisesRegex(r.Rejected,'SCOPE_CEILING'):self.check()
    def test_protected_manifest_cannot_select_active(self):
        m=copy.deepcopy(self.e.m);m['project']=r.PROJECT
        with self.assertRaisesRegex(r.Rejected,'SCOPE_CEILING'):self.check(m=m)
    def test_expired_request(self):
        self.envelope['payload']['expires']=int(time.time())-1;self.resign()
        with self.assertRaisesRegex(r.Rejected,'REQUEST_STALE'):self.check()
    def test_excessive_validity(self):
        self.envelope['payload']['expires']+=1;self.resign()
        with self.assertRaisesRegex(r.Rejected,'REQUEST_STALE'):self.check()
    def test_future_issue_time(self):
        self.envelope['payload']['issued']+=100;self.resign()
        with self.assertRaisesRegex(r.Rejected,'REQUEST_STALE'):self.check()
    def test_reused_request(self):
        with self.assertRaisesRegex(r.Rejected,'ALREADY_USED'):self.check(used={self.envelope['payload']['id']})
    def test_wrong_operation(self):
        with self.assertRaisesRegex(r.Rejected,'BINDING'):self.check(op='rollback')
    def test_tampered_manifest_binding(self):
        self.envelope['payload']['manifest_sha256']='0'*64;self.resign()
        with self.assertRaisesRegex(r.Rejected,'BINDING'):self.check()
    def test_tampered_configuration(self):
        self.envelope['payload']['config_sha256']='0'*64;self.resign()
        with self.assertRaisesRegex(r.Rejected,'BINDING'):self.check()
    def test_tampered_dataset(self):
        self.envelope['payload']['dataset_sha256']='0'*64;self.resign()
        with self.assertRaisesRegex(r.Rejected,'BINDING'):self.check()
    def test_unapproved_maintenance(self):
        self.envelope['payload']['maintenance'].append('protected');self.resign()
        with self.assertRaisesRegex(r.Rejected,'BINDING'):self.check()
    def test_unknown_rollback(self):
        self.envelope['payload']['rollback']=r.NEW;self.resign()
        with self.assertRaisesRegex(r.Rejected,'BINDING'):self.check()
    def test_cannot_claim_owner_approval(self):
        self.envelope['payload']['issuer']='OWNER';self.resign()
        with self.assertRaisesRegex(r.Rejected,'BINDING'):self.check()
    def test_signature_tamper(self):
        self.envelope['signature']=x.base64.b64encode(b'0'*64).decode()
        with self.assertRaisesRegex(r.Rejected,'SIGNATURE'):self.check()
    def test_extra_field_not_approval_bypass(self):
        self.envelope['payload']['force']=True;self.resign()
        with self.assertRaisesRegex(r.Rejected,'REQUEST_SHAPE'):self.check()
    def test_exclusive_lock(self):
        import tempfile
        from pathlib import Path
        fixture=Path(tempfile.mkdtemp(prefix='unit-lock-',dir=x.OUT))
        # Test a separate real OS lock; never contend with the live rehearsal's
        # operation lock. ACL enforcement is tested on the real private root.
        with mock.patch.object(x,'PRIVATE',fixture),mock.patch.object(x,'private_acl'):
            with x.ProjectLock():
                with self.assertRaisesRegex(r.Rejected,'LOCK_BUSY'):
                    with x.ProjectLock():pass
            with x.ProjectLock():pass
    def test_journal_mac_tamper_rejected(self):
        p=x.PRIVATE/'fixtures/unit-journal.json';x.sealed_write(p,{'generation':2})
        v=json.loads(p.read_text());v['body']['generation']=0;x.jwrite(p,v)
        with self.assertRaisesRegex(r.Rejected,'TAMPER'):x.sealed_read(p)
    def test_encryption_aad_scope_bound(self):
        key=x.AESGCM.generate_key(256);cipher=x.AESGCM(key);nonce=os.urandom(12);data=cipher.encrypt(nonce,b'declared fixture',b'projectA')
        with self.assertRaises(Exception):cipher.decrypt(nonce,data,b'projectB')
    def test_unsafe_archive_link_rejected(self):
        import io,tarfile
        b=io.BytesIO()
        with tarfile.open(fileobj=b,mode='w') as t:
            m=tarfile.TarInfo('../outside');m.size=1;t.addfile(m,io.BytesIO(b'x'))
        with self.assertRaisesRegex(r.Rejected,'ARCHIVE_PATH_OR_LINK'):x.safe_archive(b.getvalue())
    def test_archive_helper_keeps_stdin_open(self):
        d=mock.Mock();d.raw.return_value=b'fixture';e=x.Executor(docker=d)
        e.helper('unit',['-xf','-'],data=b'declared test archive')
        self.assertIn('--interactive',d.raw.call_args.args)
    def test_restore_clone_preserves_entrypoint_and_tls_hostname(self):
        op='a'*32;d=mock.Mock();d.rows.return_value=[]
        d.owned.return_value={'Image':'sha256:fixture','Config':{'Env':['DECLARED_TEST_FIXTURE=1'],'User':'0:0',
            'Entrypoint':['bash','-ec'],'Cmd':['exec declared-fixture'],'Healthcheck':{'Test':['CMD-SHELL','true']}},
            'Mounts':[{'Name':x.LANE+'_mysql-data','Destination':'/var/lib/mysql','RW':True}]}
        dest=x.LANE+'_phase23restore_unit_mysql-data'
        d.volumes.return_value=[{'Labels':{'io.zerotrust.scope':x.LANE,'io.zerotrust.restore':op}}]
        e=x.Executor(docker=d);e.clone_restore_service('mysql',x.LANE+'-phase23restore-unit',{x.LANE+'_mysql-data':dest},op)
        args=d.raw.call_args.args
        self.assertEqual(args[args.index('--entrypoint')+1],'bash');self.assertEqual(args[-3:],('sha256:fixture','-ec','exec declared-fixture'))
        self.assertIn('mysql:127.0.0.1',args);self.assertIn('none',args)
        d.raw.reset_mock()
        with self.assertRaisesRegex(r.Rejected,'RESTORE_VOLUME_SCOPE'):
            e.clone_restore_service('mysql',x.LANE+'-phase23restore-unit',{x.LANE+'_mysql-data':'protected-active-data'},op)
        d.raw.assert_not_called()


class InterruptedRollbackTests(unittest.TestCase):
    def setUp(self):
        self.e=x.Executor(docker=mock.Mock())
        self.before={'mode':'PROMOTED','risk':'recorded-disposable-promoted','manifest':self.e.digest,'operation':'prior-apply'}
        self.target={'id':'a'*32,'operation':'rollback','before':self.before,'running_before':dict.fromkeys(x.SERVICES,True)}
        self.e.state=mock.Mock(return_value=self.before)
        for method in ('verify_new','start_set','verify_runtime','save_state','quiesce','stage'):setattr(self.e,method,mock.Mock())
        self.e.maintenance=mock.Mock()
    def test_finish_interrupted_rollback_with_current_storage(self):
        self.e.recover_rollback(self.target,'BASELINE')
        self.e.d.stop.assert_called_once_with(self.before['risk'])
        self.e.maintenance.start_internal.assert_called_once_with(self.target,self.e.name('risk'))
        self.assertEqual(self.e.save_state.call_args.args[0]['mode'],'BASELINE')
        self.e.d.raw.assert_not_called()
    def test_abort_uncommitted_rollback_to_recorded_promoted(self):
        self.e.recover_rollback(self.target,'PROMOTED')
        self.e.d.stop.assert_called_once_with(self.e.name('risk'))
        self.e.maintenance.start_internal.assert_called_once_with(self.target,self.before['risk'])
        self.e.save_state.assert_not_called();self.e.d.raw.assert_not_called()
    def test_committed_rollback_cannot_repromote_by_recovery(self):
        self.e.state.return_value={'mode':'BASELINE','risk':self.e.name('risk'),'manifest':self.e.digest,'operation':self.target['id']}
        with self.assertRaisesRegex(r.Rejected,'REQUIRES_NEW_APPLY'):self.e.recover_rollback(self.target,'PROMOTED')
        self.e.d.stop.assert_not_called();self.e.start_set.assert_not_called()
    def test_unknown_rollback_state_stays_fail_closed(self):
        self.e.state.return_value={**self.before,'operation':'foreign-operation'}
        with self.assertRaisesRegex(r.Rejected,'STATE_DRIFT'):self.e.recover_rollback(self.target,'BASELINE')
        self.e.d.stop.assert_not_called();self.e.start_set.assert_not_called()


if __name__=='__main__':unittest.main(verbosity=2)
