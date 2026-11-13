"""Small owner-helper checks. TEST keys stay in RAM; no owner setup/sign execution."""
import base64
import time
import unittest
from unittest import mock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,BestAvailableEncryption,load_pem_private_key
import owner_authorize as o
import promotion_context as c
import risk_promotion as r


class OwnerHelperTests(unittest.TestCase):
    def setUp(self):self.m=r.json_bytes(c.DESCRIPTOR.read_bytes())
    def test_frozen_reviewed_digests(self):
        self.assertEqual(r.sha_file(c.DESCRIPTOR),o.DESCRIPTOR_SHA)
        self.assertEqual(r.sha_file(c.PACKET),o.PACKET_SHA)
    def test_no_apply_option(self):
        with self.assertRaisesRegex(r.Rejected,'OUT_OF_SCOPE'):o.payload(self.m,'apply')
    def test_restore_requires_exact_id(self):
        with self.assertRaisesRegex(r.Rejected,'CHECKPOINT_ID'):o.payload(self.m,'restore-verify','PLACEHOLDER')
    def test_no_checkpoint_in_backup_request(self):
        with self.assertRaisesRegex(r.Rejected,'MUST_NOT_REFERENCE'):o.payload(self.m,'backup-only','a'*32)
    def test_console_required_before_owner_actions(self):
        with mock.patch.object(o.sys.stdin,'isatty',return_value=False):
            with self.assertRaisesRegex(r.Rejected,'PRIVATE_INTERACTIVE_TERMINAL'):o.owner_console()
    def test_encrypted_key_roundtrip_in_memory_only(self):
        key=Ed25519PrivateKey.generate();secret=b'TEST-only-memory-passphrase'
        pem=key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,BestAvailableEncryption(secret))
        self.assertIn(b'ENCRYPTED PRIVATE KEY',pem)
        recovered=load_pem_private_key(pem,secret)
        self.assertEqual(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),recovered.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
        with self.assertRaises(ValueError):load_pem_private_key(pem,b'wrong-TEST-password')
    def test_helper_payloads_match_frozen_verifier_with_test_signer_only(self):
        key=Ed25519PrivateKey.generate();pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        anchor={'kind':'OWNER_CONTROLLED_ACTIVE_ONLY','project':r.PROJECT,'owner_sid':self.m['owner_sid'],
            'issuer':'OWNER_EXPLICIT_ACTIVE_AUTHORIZATION','descriptor_sha256':o.DESCRIPTOR_SHA,'packet_sha256':o.PACKET_SHA,
            'expires':int(time.time())+300,'operations':list(o.ALLOWED),'public_key':base64.b64encode(pub).decode(),'public_key_sha256':r.sha(pub)}
        for operation,checkpoint in [('backup-only',None),('restore-verify','a'*32)]:
            payload=o.payload(self.m,operation,checkpoint)
            envelope={'payload':payload,'signature':base64.b64encode(key.sign(c.canonical(payload))).decode()}
            result=c.verify_owner_request(envelope,self.m,o.DESCRIPTOR_SHA,o.PACKET_SHA,operation,set(),anchor)
            self.assertEqual(result['operation'],operation)
            self.assertEqual(result['expires']-result['issued'],600)


if __name__=='__main__':unittest.main(verbosity=2)
