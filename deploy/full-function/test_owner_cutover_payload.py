"""New runbook producer checks only. No keys/signatures/anchor or operation created."""
import base64
import time
import unittest
from unittest import mock
import owner_authorize as o
import promotion_context as c
import risk_promotion as r


class CutoverPayloadTests(unittest.TestCase):
    def test_exact_scope_payloads_match_existing_protocol_without_signing(self):
        m=r.json_bytes(c.DESCRIPTOR.read_bytes());pub=b'\x01'*32
        anchor={'kind':'OWNER_CONTROLLED_ACTIVE_ONLY','project':r.PROJECT,'owner_sid':m['owner_sid'],
            'issuer':'OWNER_EXPLICIT_ACTIVE_AUTHORIZATION','descriptor_sha256':o.DESCRIPTOR_SHA,'packet_sha256':o.PACKET_SHA,
            'expires':int(time.time())+600,'operations':list(o.CUTOVER),'public_key':base64.b64encode(pub).decode(),'public_key_sha256':r.sha(pub)}
        cases=[('apply','a'*32,None,None),('restart',None,None,None),('rollback',None,None,None),('recover',None,'b'*32,'BASELINE')]
        for op,cp,ref,target in cases:
            p=o.cutover_payload(m,op,cp,ref,target)
            # Cryptographic verifier is already accepted. Mock only signature
            # validation here: no real or TEST authorization is signed.
            with mock.patch.object(c.Ed25519PublicKey,'from_public_bytes',return_value=mock.Mock()):
                result=c.verify_owner_request({'payload':p,'signature':base64.b64encode(b'NOT-A-SIGNATURE').decode()},m,
                    o.DESCRIPTOR_SHA,o.PACKET_SHA,op,set(),anchor)
            self.assertEqual(result['operation'],op)
            self.assertEqual(result['expires']-result['issued'],600)
    def test_apply_requires_exact_checkpoint(self):
        m=r.json_bytes(c.DESCRIPTOR.read_bytes())
        with self.assertRaisesRegex(r.Rejected,'CHECKPOINT_ID'):o.cutover_payload(m,'apply','UNKNOWN')
    def test_recovery_requires_explicit_original_operation(self):
        m=r.json_bytes(c.DESCRIPTOR.read_bytes())
        with self.assertRaisesRegex(r.Rejected,'INTERRUPTED_OPERATION_ID'):o.cutover_payload(m,'recover')
    def test_rollback_cannot_smuggle_snapshot_restore(self):
        m=r.json_bytes(c.DESCRIPTOR.read_bytes())
        with self.assertRaisesRegex(r.Rejected,'UNEXPECTED_CUTOVER_CHECKPOINT'):o.cutover_payload(m,'rollback','a'*32)
    def test_ten_minute_checkpoint_margin(self):
        ctx=mock.Mock();ctx.engine.load_checkpoint.return_value={'created':time.time()-1250}
        with self.assertRaisesRegex(r.Rejected,'LESS_THAN_10_MIN'):o.reviewed_checkpoint(ctx,'a'*32)
    def test_checkpoint_margin_accepts_fresh_verified_reference(self):
        ctx=mock.Mock();ctx.engine.load_checkpoint.return_value={'created':time.time()-300}
        self.assertIn('created',o.reviewed_checkpoint(ctx,'a'*32))
        ctx.engine.load_checkpoint.assert_called_once_with('a'*32,True)
    def test_promoted_scope_restore_needs_no_baseline_or_checkpoint(self):
        ctx=mock.Mock();ctx.engine.validate.return_value={'mode':'PROMOTED'};ctx.engine.unfinished.return_value=[]
        with mock.patch.object(o,'owner_console'),mock.patch.object(o,'frozen'),mock.patch.object(o.c,'Context',return_value=ctx),\
             mock.patch.object(o.c,'load_owner_anchor',return_value={}),mock.patch.object(o,'binding_review'),mock.patch.object(o,'approve'),\
             mock.patch.object(o.x,'jwrite') as write,mock.patch.object(o,'secure'),mock.patch.object(o.c,'owner_acl'),mock.patch('builtins.print'):
            o.scope('cutover',None)
            self.assertEqual(set(write.call_args.args[1]['operations']),set(o.CUTOVER))
            ctx.preflight.assert_not_called()
    def test_recovery_scope_does_not_grant_apply(self):
        ctx=mock.Mock();ctx.engine.unfinished.return_value=[{'id':'a'*32}]
        with mock.patch.object(o,'owner_console'),mock.patch.object(o,'frozen'),mock.patch.object(o.c,'Context',return_value=ctx),\
             mock.patch.object(o.c,'load_owner_anchor',return_value={}),mock.patch.object(o,'binding_review'),mock.patch.object(o,'approve'),\
             mock.patch.object(o.x,'jwrite') as write,mock.patch.object(o,'secure'),mock.patch.object(o.c,'owner_acl'),mock.patch('builtins.print'):
            o.scope('recovery',None)
            self.assertEqual(write.call_args.args[1]['operations'],['recover'])


if __name__=='__main__':unittest.main(verbosity=2)
