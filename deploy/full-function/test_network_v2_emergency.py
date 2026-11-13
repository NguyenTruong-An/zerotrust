"""Emergency extension only: RAM signatures/fake Docker; never an owner key or grant."""
import base64
import contextlib
import contextvars
import copy
import json
import types
import unittest
from unittest import mock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import network_v2_rollout as n
import network_v2_emergency as e


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.hashpatch=mock.patch.object(n.r,'sha_file',side_effect=lambda path:'EMERGENCY' if path==e.DESCRIPTOR else 'PARENT_D' if path==n.DESCRIPTOR else 'PARENT_P')
        self.hashpatch.start();self.addCleanup(self.hashpatch.stop)
        self.m={'owner_sid':'RAM','release':{},'checkpoint_rules':{}}
        self.em={'parent_descriptor_sha256':'PARENT_D','quarantine':{'id':'EXACT_STOPPED_ID'}}
        self.signer=Ed25519PrivateKey.generate();pub=self.signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        self.anchor={'kind':'OWNER_CONTROLLED_NETWORK_V2_SHADOW_ONLY','project':n.PROJECT,'owner_sid':'RAM','issuer':n.ISSUER,
                     'descriptor_sha256':'PARENT_D','packet_sha256':'PARENT_P','expires':2000,'operations':['recover','rollback'],
                     'public_key':base64.b64encode(pub).decode(),'public_key_sha256':n.sha(pub)}
        payload=n.payload(self.m,'recover',recover_of=e.OP,recover_target='BASELINE',now=1000,ident='a'*32)
        self.core=self.sign(payload);self.extension=self.sign(e.extension_payload(self.core,self.em))
    def sign(self,p):return {'payload':copy.deepcopy(p),'signature':base64.b64encode(self.signer.sign(n.canonical(p))).decode()}
    def verify(self):
        n.verify(self.core,self.m,'PARENT_D','PARENT_P','recover',set(),self.anchor,now=1100)
        e.verify_extension(self.extension,self.core,self.em,self.anchor,now=1100)
    def test_both_signatures_exact_same_owner_and_request_valid(self):self.verify()
    def test_missing_extension_rejected(self):
        self.extension=None
        with self.assertRaisesRegex(n.r.Rejected,'EXTENSION_SHAPE'):self.verify()
    def test_core_signature_cannot_authorize_unsigned_extension(self):
        self.extension['signature']=self.core['signature']
        with self.assertRaisesRegex(n.r.Rejected,'SIGNATURE_INVALID'):self.verify()
    def test_changed_quarantine_binding_rejected(self):
        self.em['quarantine']['id']='FOREIGN'
        with self.assertRaisesRegex(n.r.Rejected,'EXTENSION_BINDING'):self.verify()
    def test_extension_is_not_reusable_for_a_new_core_request(self):
        self.core['payload']['id']='b'*32;self.core=self.sign(self.core['payload'])
        with self.assertRaisesRegex(n.r.Rejected,'EXTENSION_BINDING'):self.verify()
    def test_expired_original_request_rejected(self):
        with self.assertRaisesRegex(n.r.Rejected,'EXPIRED'):
            n.verify(self.core,self.m,'PARENT_D','PARENT_P','recover',set(),self.anchor,now=1601)
    def test_consumed_request_cannot_be_replayed(self):
        with self.assertRaisesRegex(n.r.Rejected,'ALREADY_USED'):
            n.verify(self.core,self.m,'PARENT_D','PARENT_P','recover',{'a'*32},self.anchor,now=1100)
    def test_BASELINE_still_requires_rollback_scope(self):
        self.anchor['operations']=['recover']
        with self.assertRaisesRegex(n.r.Rejected,'REQUIRES_ROLLBACK_SCOPE'):self.verify()
    def test_separate_key_cannot_sign_extension(self):
        other=Ed25519PrivateKey.generate()
        self.extension['signature']=base64.b64encode(other.sign(n.canonical(self.extension['payload']))).decode()
        with self.assertRaisesRegex(n.r.Rejected,'SIGNATURE_INVALID'):self.verify()


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.c=mock.Mock();self.c.m={'services':{'risk':{'name':'baseline-risk'}},'release':{'risk_override':{'mode':'SHADOW','retention':False}}}
        self.c.module.public_witness.return_value={'exact':'contract'}
        self.c.executor.d.owned.return_value={'Config':{'Env':['JAVA_HOME=/synthetic','SPRING_APPLICATION_JSON={}']}}
        self.actual=['JAVA_HOME=/synthetic','SPRING_APPLICATION_JSON='+json.dumps(self.c.m['release']['risk_override'])]
        self.row={'Id':'exact-id','Name':'/exact-name','State':{'Running':False,'Status':'created'},'Config':{'Env':list(self.actual)}}
        self.record={'id':'exact-id','name':'exact-name','witness':{'exact':'contract'},'reproduced_environment_sha256':n.sha(json.dumps(sorted(self.actual)).encode())}
    def test_all_original_guards_are_called_without_modifying_real_context_or_starting(self):
        before=copy.deepcopy(self.c.m)
        with mock.patch.object(n.Context,'verify_replacement') as original:
            e.stopped_candidate_guard(self.c,self.row,self.record)
            proxy,row,op=original.call_args.args
            self.assertEqual(proxy.m['release']['risk_environment_sha256'],self.record['reproduced_environment_sha256'])
            self.assertEqual(row,self.row);self.assertEqual(op,e.OP)
        self.assertEqual(self.c.m,before);self.c.executor.d.start.assert_not_called();self.c.executor.d.raw.assert_not_called()
    def test_running_candidate_cannot_be_quarantined_or_started(self):
        self.row['State']['Running']=True
        with self.assertRaisesRegex(n.r.Rejected,'NOT_EXACT_STOPPED'):e.stopped_candidate_guard(self.c,self.row,self.record)
    def test_exited_or_previously_run_candidate_rejected(self):
        self.row['State']['Status']='exited'
        with self.assertRaisesRegex(n.r.Rejected,'NOT_EXACT_STOPPED'):e.stopped_candidate_guard(self.c,self.row,self.record)
    def test_wrong_container_id_rejected(self):
        self.row['Id']='foreign'
        with self.assertRaisesRegex(n.r.Rejected,'NOT_EXACT_STOPPED'):e.stopped_candidate_guard(self.c,self.row,self.record)
    def test_changed_mount_or_hardening_contract_rejected(self):
        self.c.module.public_witness.return_value={'changed':'mount'}
        with self.assertRaisesRegex(n.r.Rejected,'CONTRACT_DRIFT'):e.stopped_candidate_guard(self.c,self.row,self.record)
    def test_non_JSON_environment_change_not_excused(self):
        self.row['Config']['Env'][0]='JAVA_HOME=/tampered'
        with self.assertRaisesRegex(n.r.Rejected,'NOT_REPRODUCIBLE'):e.stopped_candidate_guard(self.c,self.row,self.record)
    def test_JSON_policy_change_not_excused(self):
        self.row['Config']['Env'][1]='SPRING_APPLICATION_JSON={"mode":"ENFORCED"}'
        with self.assertRaisesRegex(n.r.Rejected,'NOT_REPRODUCIBLE'):e.stopped_candidate_guard(self.c,self.row,self.record)
    def test_duplicate_environment_keys_rejected(self):
        self.row['Config']['Env'].append('JAVA_HOME=/synthetic')
        with self.assertRaisesRegex(n.r.Rejected,'NOT_REPRODUCIBLE'):e.stopped_candidate_guard(self.c,self.row,self.record)
    def test_wrong_reproduced_hash_rejected(self):
        self.record['reproduced_environment_sha256']='wrong'
        with self.assertRaisesRegex(n.r.Rejected,'EXACT_ENV_HASH_DRIFT'):e.stopped_candidate_guard(self.c,self.row,self.record)
    def test_original_guard_failure_still_propagates(self):
        with mock.patch.object(n.Context,'verify_replacement',side_effect=n.r.Rejected('SHADOW_REPLACEMENT_ID_DRIFT')):
            with self.assertRaisesRegex(n.r.Rejected,'ID_DRIFT'):e.stopped_candidate_guard(self.c,self.row,self.record)


class ScopeAndFailureTests(unittest.TestCase):
    def test_apply_restart_or_wrong_recovery_scope_rejected_before_parent_signature_admission(self):
        c=object.__new__(e.EmergencyContext)
        for operation,ident,target in [('apply',e.OP,'BASELINE'),('restart',e.OP,'BASELINE'),('recover','b'*32,'BASELINE'),('recover',e.OP,'SHADOW')]:
            with self.subTest(operation=operation,target=target),mock.patch.object(n.Context,'authorize') as parent:
                with self.assertRaisesRegex(n.r.Rejected,'ONLY_EXACT_BASELINE'):
                    c.authorize({'payload':{'recover_of':ident,'recover_target':target}},operation)
                parent.assert_not_called()
    def test_recovery_intent_precedes_mutation_and_partial_failure_stays_unfinished(self):
        c=object.__new__(e.EmergencyContext);c.grant=contextvars.ContextVar('RAM_EMERGENCY',default=False)
        c.extension={'payload':'RAM'};c.em={'quarantine':{'id':'exact-stopped'}};c.executor=mock.Mock();c.old=mock.Mock();c.old.module.ProjectLock=contextlib.nullcontext
        c.authorize=mock.Mock(return_value={'recover_target':'BASELINE'});c.validate=mock.Mock();c.initialize=mock.Mock()
        c.m={'services':{'ingress':{'name':'owned-ingress'}}};c.recovery_schema_allowed=False
        j={'id':'a'*32,'stage':'AUTHORIZED','before':{'mode':'BASELINE'}};c.executor.new_operation.return_value=j
        c.executor.stage.side_effect=lambda journal,stage,**fields:journal.update(stage=stage,**fields)
        with mock.patch.object(n.r,'sha_file',return_value='EMERGENCY'),mock.patch.object(n.Context,'recover',side_effect=n.r.Rejected('PARTIAL_RESUME_FAILURE')):
            with self.assertRaisesRegex(n.r.Rejected,'PARTIAL_RESUME_FAILURE'):c.execute({},'recover')
        self.assertEqual(j['stage'],'FAILED_CLOSED_RECOVERY_REQUIRED')
        c.executor.finish.assert_not_called();c.executor.d.stop.assert_called_once_with('owned-ingress')
        self.assertFalse(c.grant.get())


if __name__=='__main__':unittest.main()
