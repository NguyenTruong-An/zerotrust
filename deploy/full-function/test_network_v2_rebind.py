"""Changed controller/binding boundaries only. Fake Docker, RAM signer, temp storage."""
import contextlib
import contextvars
import copy
import json
import hashlib
import hmac
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import network_v2_rollout as n
import owner_shadow_authorize as a


class CheckpointCompletionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.ident='a'*32
        self.patcher=mock.patch.object(n,'PRIVATE',self.root);self.patcher.start();self.addCleanup(self.patcher.stop)
        (self.root/'keys').mkdir();self.key=self.root/'keys'/(self.ident+'.key');self.key.write_bytes(b'K'*32)
        self.c=object.__new__(n.Context);self.c.m={'volumes':[n.PROJECT+'_risk-config',n.PROJECT+'_mysql-data']};self.c.digest='fixture-digest'
        self.c.module=mock.Mock();self.c.executor=mock.Mock()
        self.cp={'id':self.ident,'configs':{n.PROJECT+'_risk-config':'config-risk-config'},
                 'files':dict.fromkeys(('sql','redis','runtime-contract','execution-manifest','config-risk-config'),'fixture-hash'),
                 'created':1000,'restore_verified':False}
        self.c.executor.load_checkpoint.return_value=self.cp
        self.j={'id':self.ident,'manifest':self.c.digest,'operation':'backup-only','stage':'DONE','status':'DONE','checkpoint':self.ident}
        self.c.module.sealed_read.return_value=self.j
        self.c.executor.unseal.side_effect=lambda cp,label: n.canonical(self.c.m) if label=='execution-manifest' else b'SYNTHETIC'

    def test_complete_requires_authenticated_ciphertexts_and_done_journal(self):
        with mock.patch.object(n.time,'time',return_value=1100):result=self.c.checkpoint_status(self.ident)
        self.assertEqual(result['status'],'COMPLETE');self.assertFalse(result['independent_restore_verified'])
        self.assertFalse(result['APPLY_authorized']);self.assertEqual(self.c.executor.unseal.call_count,5)
        self.c.executor.d.raw.assert_not_called();self.c.executor.save_state.assert_not_called()

    def test_request_id_without_checkpoint_is_not_success(self):
        self.c.executor.load_checkpoint.side_effect=FileNotFoundError()
        with self.assertRaises(FileNotFoundError):self.c.checkpoint_status(self.ident)
        self.c.executor.unseal.assert_not_called()

    def test_incomplete_journal_is_never_complete_even_if_checkpoint_file_exists(self):
        self.j.update(status='RUNNING',stage='CHECKPOINT_WRITTEN')
        with self.assertRaisesRegex(n.r.Rejected,'BACKUP_NOT_COMPLETE'):self.c.checkpoint_status(self.ident)
        self.c.executor.unseal.assert_not_called()

    def test_missing_file_scope_rejected(self):
        del self.cp['files']['sql']
        with self.assertRaisesRegex(n.r.Rejected,'SCOPE_INCOMPLETE'):self.c.checkpoint_status(self.ident)

    def test_checkpoint_ID_cannot_differ_from_the_request_and_journal(self):
        self.cp['id']='b'*32
        with self.assertRaisesRegex(n.r.Rejected,'BACKUP_NOT_COMPLETE'):self.c.checkpoint_status(self.ident)

    def test_missing_key_rejected(self):
        self.key.unlink()
        with self.assertRaisesRegex(n.r.Rejected,'KEY_MISSING'):self.c.checkpoint_status(self.ident)

    def test_AES_authentication_failure_rejected(self):
        self.c.executor.unseal.side_effect=n.r.Rejected('CHECKPOINT_AUTHENTICATION')
        with self.assertRaisesRegex(n.r.Rejected,'CHECKPOINT_AUTHENTICATION'):self.c.checkpoint_status(self.ident)

    def test_wrong_embedded_manifest_rejected(self):
        self.c.executor.unseal.side_effect=lambda cp,label:b'{}'
        with self.assertRaisesRegex(n.r.Rejected,'MANIFEST_DRIFT'):self.c.checkpoint_status(self.ident)


class SharedLockTests(unittest.TestCase):
    def setUp(self):
        self.c=object.__new__(n.Context);self.c.grant=contextvars.ContextVar('fake-grant',default=False)
        self.c.recovery_schema_allowed=False;self.c.authorize=mock.Mock(return_value={'recover_target':None})
        self.c.validate=mock.Mock();self.c.initialize=mock.Mock();self.c.executor=mock.Mock();self.c.old=mock.Mock()
        self.events=[]
        events=self.events
        @contextlib.contextmanager
        def lock():
            events.append('lock-enter')
            try:yield
            finally:events.append('lock-exit')
        self.c.old.module.ProjectLock=lock
        self.c.authorize.side_effect=lambda *args:(events.append('admit'),{'recover_target':None})[1]
        self.c.executor.backup.side_effect=lambda env:events.append('backup')

    def test_backup_executes_under_same_shared_lock_with_second_authorization_check(self):
        self.c.execute({},'backup-only')
        self.assertEqual(self.events,['admit','lock-enter','admit','backup','lock-exit'])
        self.assertFalse(self.c.grant.get())

    def test_busy_shared_lock_prevents_initialization_and_backup(self):
        self.c.old.module.ProjectLock=mock.Mock(side_effect=n.r.Rejected('PROJECT_OPERATION_LOCK_BUSY'))
        with self.assertRaisesRegex(n.r.Rejected,'LOCK_BUSY'):self.c.execute({},'backup-only')
        self.c.initialize.assert_not_called();self.c.executor.backup.assert_not_called();self.assertFalse(self.c.grant.get())

    def test_expiry_or_replay_under_lock_prevents_backup(self):
        self.c.authorize.side_effect=[{'recover_target':None},n.r.Rejected('SHADOW_REQUEST_ALREADY_USED')]
        with self.assertRaisesRegex(n.r.Rejected,'ALREADY_USED'):self.c.execute({},'backup-only')
        self.c.initialize.assert_not_called();self.c.executor.backup.assert_not_called();self.assertFalse(self.c.grant.get())


class CrossBindingAuthorizationTests(unittest.TestCase):
    def test_same_owner_signature_for_old_descriptor_cannot_authorize_new_descriptor(self):
        from test_network_v2_rollout import AuthorizationTests
        fixture=AuthorizationTests('test_valid_backup_RAM_only');fixture.setUp()
        with self.assertRaisesRegex(n.r.Rejected,'SHADOW_REQUEST_BINDING'):
            n.verify(fixture.envelope(),fixture.m,'NEW_DESCRIPTOR','NEW_PACKET','backup-only',set(),fixture.anchor,now=1100)

    def test_new_control_namespace_and_anchor_cannot_overwrite_recovered_v1(self):
        self.assertNotEqual(n.PRIVATE,n.PREVIOUS_PRIVATE)
        self.assertEqual(str(n.ANCHOR).replace('\\','/'),(Path.home()/'.zerotrust-owner/network-v2-shadow-v2/anchor.json').as_posix())
        self.assertNotEqual(n.DESCRIPTOR,n.PREVIOUS_DESCRIPTOR)
        self.assertNotEqual(n.PACKET,n.PREVIOUS_PACKET)


class RecoveryScopeTests(unittest.TestCase):
    def setUp(self):
        self.ctx=mock.Mock();self.ctx.m={'owner_sid':'fixture'};self.ctx.digest='d'*64
        self.target={'id':'a'*32,'manifest':self.ctx.digest,'status':'RUNNING'}
        self.ctx.executor.unfinished.return_value=[self.target]
        self.anchor={'kind':'OWNER_CONTROLLED_NETWORK_V2_SHADOW_ONLY','project':n.PROJECT,'owner_sid':'fixture',
                     'issuer':n.ISSUER,'descriptor_sha256':self.ctx.digest,'packet_sha256':'p'*64,
                     'operations':['backup-only','restore-verify'],'public_key_sha256':'k'*64}

    def call(self,target='BASELINE'):
        with mock.patch.object(a.old,'owner_console'),mock.patch.object(a,'review'),\
             mock.patch.object(a.n,'Context',return_value=self.ctx),mock.patch.object(a.old.c,'owner_acl'),\
             mock.patch.object(a.n.r,'json_bytes',return_value=self.anchor),mock.patch.object(a.n.ANCHOR.__class__,'read_bytes',return_value=b'fixture'),\
             mock.patch.object(a.n.r,'sha_file',return_value='p'*64),mock.patch.object(a.old,'approve') as approve,\
             mock.patch.object(a,'key'),mock.patch.object(a.n,'sha',return_value='k'*64),\
             mock.patch.object(a.old.x,'jwrite') as write,mock.patch.object(a.old,'secure'):
            a.scope_recovery('a'*32,target)
            return copy.deepcopy(write.call_args.args[1]),approve

    def test_baseline_recovery_scope_needs_no_checkpoint_and_grants_no_apply_restart(self):
        result,approve=self.call()
        self.assertEqual(set(result['operations']),{'backup-only','restore-verify','recover','rollback'})
        self.ctx.executor.load_checkpoint.assert_not_called();self.ctx.execute.assert_not_called()
        approve.assert_called_once_with('AUTHORIZE NETWORK V2 RECOVERY '+'a'*32+' BASELINE')

    def test_stopped_recovery_does_not_grant_rollback(self):
        result,_=self.call('STOPPED')
        self.assertEqual(set(result['operations']),{'backup-only','restore-verify','recover'})

    def test_no_pending_target_rejected_before_signer_or_write(self):
        self.ctx.executor.unfinished.return_value=[]
        with self.assertRaisesRegex(n.r.Rejected,'EXACT_PENDING_OPERATION'):self.call()

    def test_wrong_anchor_binding_rejected(self):
        self.anchor['descriptor_sha256']='wrong'
        with self.assertRaisesRegex(n.r.Rejected,'ANCHOR_REVIEW_REQUIRED'):self.call()


class RecoveryRegressionTests(unittest.TestCase):
    def test_recover_baseline_quiesces_then_resumes_same_pair_without_DB_restore_or_migration(self):
        c=object.__new__(n.Context);c.require_grant=mock.Mock();c.digest='fixture';c.executor=mock.Mock();c.module=mock.Mock()
        target={'id':'a'*32,'manifest':c.digest,'status':'RUNNING','operation':'backup-only',
                'before':{'mode':'BASELINE','risk':'same-risk','keycloak':'same-keycloak'}}
        c.module.sealed_read.return_value=target;c.executor.d.rows.return_value=[]
        c.quiesce=mock.Mock();c.resume=mock.Mock();c.migrate=mock.Mock()
        j={'id':'b'*32,'request':{'recover_of':target['id'],'recover_target':'BASELINE'}}
        c.recover(j)
        c.quiesce.assert_called_once_with(target,True);c.resume.assert_called_once_with(target,target['before'])
        c.executor.stage.assert_called_once_with(target,'RECOVERED',status='DONE',recovered_by=j['id'])
        c.migrate.assert_not_called();c.executor.restore_verify.assert_not_called();c.executor.d.raw.assert_not_called()

    def test_resume_Risk_uses_custom_probe_and_ingress_opens_only_after_verification(self):
        c=object.__new__(n.Context);c.require_grant=mock.Mock();c.executor=mock.Mock();c.selection=None
        c.m={'services':{'ingress':{'name':'ingress'}}};c.executor.name.side_effect=lambda service:service
        c.executor.d.owned.side_effect=lambda name:{'State':{'Running':False if name=='ingress' and c.executor.d.start.call_count<9 else True}}
        c.verify_runtime=mock.Mock();j={'running_before':dict.fromkeys(n.SERVICES,True)}
        selected={'mode':'BASELINE','risk':'same-risk','keycloak':'keycloak'}
        calls=[];c.executor.d.start.side_effect=lambda name:calls.append(name)
        c.verify_runtime.side_effect=lambda:calls.append('internal-verify')
        c.resume(j,selected)
        c.executor.d.health.assert_any_call('same-risk',True)
        self.assertLess(calls.index('internal-verify'),calls.index('ingress'))
        self.assertIsNone(c.selection);c.executor.d.stop.assert_not_called()


class PredecessorBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.previous=self.root/'previous';self.previous.mkdir()
        (self.previous/'journal').mkdir();self.key=b'T'*32;(self.previous/'state.key').write_bytes(self.key)
        self.state={'manifest':n.PREVIOUS_SHA,'mode':'BASELINE','risk':'same-risk','keycloak':'same-keycloak'}
        self.write('state.json',self.state);self.write('journal/closed.json',{'status':'DONE'})
        self.desc=self.root/'old-descriptor';self.packet=self.root/'old-packet'
        self.m={'predecessor':{'descriptor_sha256':n.PREVIOUS_SHA,'packet_sha256':n.PREVIOUS_PACKET_SHA},
                'services':{'risk':{'name':'same-risk'},'keycloak':{'name':'same-keycloak'}}}
        self.refresh()
        def file_sha(path):
            if path==self.desc:return n.PREVIOUS_SHA
            if path==self.packet:return n.PREVIOUS_PACKET_SHA
            return hashlib.sha256(path.read_bytes()).hexdigest()
        for patcher in (mock.patch.object(n,'PREVIOUS_PRIVATE',self.previous),mock.patch.object(n,'PREVIOUS_DESCRIPTOR',self.desc),
                        mock.patch.object(n,'PREVIOUS_PACKET',self.packet),mock.patch.object(n.r,'ROOT',self.root),
                        mock.patch.object(n.r,'sha_file',side_effect=file_sha)):
            patcher.start();self.addCleanup(patcher.stop)

    def write(self,relative,body):
        (self.previous/relative).write_bytes(n.canonical({'body':body,'mac':hmac.digest(self.key,n.canonical(body),'sha256').hex()}))

    def refresh(self):
        self.m['predecessor']['control_files_sha256']={str(p.relative_to(self.root)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.previous.rglob('*') if p.is_file()}

    def test_closed_predecessor_read_only_and_identity_validated(self):
        before=dict(self.m['predecessor']['control_files_sha256']);n.predecessor_guard(self.m);self.refresh()
        self.assertEqual(before,self.m['predecessor']['control_files_sha256'])

    def test_any_historical_journal_change_rejected(self):
        with (self.previous/'journal/closed.json').open('ab') as f:f.write(b' ')
        with self.assertRaisesRegex(n.r.Rejected,'STATE_OR_JOURNAL_DRIFT'):n.predecessor_guard(self.m)

    def test_new_unfinished_predecessor_operation_rejected(self):
        self.write('journal/new.json',{'status':'RUNNING'});self.refresh()
        with self.assertRaisesRegex(n.r.Rejected,'OPERATION_PENDING'):n.predecessor_guard(self.m)

    def test_MAC_validation_is_not_replaced_by_public_hashes(self):
        (self.previous/'state.json').write_bytes(n.canonical({'body':self.state,'mac':'0'*64}));self.refresh()
        with self.assertRaisesRegex(n.r.Rejected,'MAC_INVALID'):n.predecessor_guard(self.m)

    def test_predecessor_must_still_select_same_baseline_pair(self):
        self.state['risk']='wrong-image-container';self.write('state.json',self.state);self.refresh()
        with self.assertRaisesRegex(n.r.Rejected,'NOT_BASELINE'):n.predecessor_guard(self.m)


if __name__=='__main__':unittest.main()
