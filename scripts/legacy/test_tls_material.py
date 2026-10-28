"""PKI maintenance invariants; entirely in memory, no Docker or live CA writes."""
import datetime as dt
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'deploy/legacy'))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import tls_material as tls


class TlsMaterialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'TEST ONLY CA')])
        cls.ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                  .public_key(cls.key.public_key()).serial_number(x509.random_serial_number())
                  .not_valid_before(cls.now - dt.timedelta(days=1)).not_valid_after(cls.now + dt.timedelta(days=30))
                  .add_extension(x509.BasicConstraints(True, 0), True)
                  .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
                  .sign(cls.key, hashes.SHA256()))
        cls.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'gateway')]))
                    .issuer_name(name).public_key(cls.leaf_key.public_key()).serial_number(123)
                    .not_valid_before(cls.now - dt.timedelta(hours=1)).not_valid_after(cls.now + dt.timedelta(days=10))
                    .add_extension(x509.BasicConstraints(False, None), True)
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName('gateway'), x509.DNSName('localhost')]), False)
                    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                    .sign(cls.key, hashes.SHA256()))

    def old_crl(self, serial=999):
        entry = (x509.RevokedCertificateBuilder().serial_number(serial)
                 .revocation_date(self.now - dt.timedelta(days=1))
                 .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), False).build())
        return (x509.CertificateRevocationListBuilder().issuer_name(self.ca.subject)
                .last_update(self.now - dt.timedelta(days=2)).next_update(self.now - dt.timedelta(days=1))
                .add_revoked_certificate(entry).add_extension(x509.CRLNumber(9999999999), False)
                .sign(self.key, hashes.SHA256()))

    def test_renewal_preserves_revocations_and_increments_number(self):
        old = self.old_crl()
        renewed = tls.renew_crl(self.ca, self.key, old, self.now)
        self.assertTrue(renewed.is_signature_valid(self.ca.public_key()))
        self.assertEqual(renewed[0].serial_number, old[0].serial_number)
        self.assertEqual(renewed[0].revocation_date_utc, old[0].revocation_date_utc)
        self.assertEqual(list(renewed[0].extensions), list(old[0].extensions))
        self.assertEqual(renewed.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number, 10000000000)
        self.assertLessEqual(renewed.last_update_utc, self.now)
        self.assertEqual(renewed.next_update_utc, self.now + dt.timedelta(days=7))

    def test_reissue_preserves_key_san_eku_expiry_and_adds_both_locations(self):
        new = tls.reissue_public_certificate(self.ca, self.key, self.cert, self.leaf_key, self.old_crl(), self.now)
        new.verify_directly_issued_by(self.ca)
        self.assertEqual(new.public_key().public_numbers(), self.cert.public_key().public_numbers())
        self.assertEqual(new.not_valid_after_utc, self.cert.not_valid_after_utc)
        self.assertNotEqual(new.serial_number, self.cert.serial_number)
        for extension in self.cert.extensions:
            self.assertEqual(new.extensions.get_extension_for_oid(extension.oid), extension)
        points = new.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        self.assertEqual(len(points), 1)
        self.assertEqual([name.value for name in points[0].full_name], list(tls.PUBLIC_CDP))

    def test_revoked_leaf_cannot_be_reissued(self):
        with self.assertRaisesRegex(ValueError, 'REVOKED_LEAF'):
            tls.reissue_public_certificate(self.ca, self.key, self.cert, self.leaf_key,
                                          self.old_crl(self.cert.serial_number), self.now)

    def test_wrong_leaf_key_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'LEAF_KEY_MISMATCH'):
            tls.reissue_public_certificate(self.ca, self.key, self.cert, self.key, self.old_crl(), self.now)

    def test_ca_key_mismatch_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'CA_KEY_MISMATCH'):
            tls.renew_crl(self.ca, self.leaf_key, self.old_crl(), self.now)

    def test_invalid_crl_signature_is_rejected(self):
        wrong = (x509.CertificateRevocationListBuilder().issuer_name(self.ca.subject)
                 .last_update(self.now).next_update(self.now + dt.timedelta(days=1))
                 .sign(self.leaf_key, hashes.SHA256()))
        with self.assertRaisesRegex(ValueError, 'OLD_CRL_INVALID'):
            tls.renew_crl(self.ca, self.key, wrong, self.now)

    def test_check_detects_missing_cdp_and_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / 'owner.json').write_text('{"owner":"' + tls.PROJECT + '"}')
            (state / 'public-ca').mkdir()
            (state / 'public-ca/ca.crt').write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
            crl = tls.renew_crl(self.ca, self.key, self.old_crl(), self.now)
            (state / 'public-ca/ca.crl').write_bytes(crl.public_bytes(serialization.Encoding.DER))
            (state / 'gateway').mkdir()
            (state / 'gateway/server.crt').write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))
            before = {p: p.read_bytes() for p in state.rglob('*') if p.is_file()}
            with self.assertRaises(x509.ExtensionNotFound):
                tls.check(state)
            self.assertEqual(before, {p: p.read_bytes() for p in state.rglob('*') if p.is_file()})


if __name__ == '__main__':
    unittest.main()
