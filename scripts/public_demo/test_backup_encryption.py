import contextlib
import io
import os
from pathlib import Path
import subprocess
import time
import unittest
from backup_encryption import encrypt,decrypt

ROOT=Path(__file__).resolve().parents[2]
AGE=os.environ.get("PD06_AGE_EXE")
MARKER=b"synthetic-PD06-backup-password-otp-token-privatekey-marker"


@unittest.skipUnless(AGE,"explicit portable age path required; no tool installation by tests")
class BackupEncryptionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=ROOT/"target/pd-02-06/backup-fixtures"/str(time.time_ns())
        for name in ("keys","archives","restored"): (cls.root/name).mkdir(parents=True)
        cls.identities=[];cls.recipients=[]
        keygen=Path(AGE).with_name("age-keygen.exe" if os.name=="nt" else "age-keygen")
        for index in range(3):
            path=cls.root/"keys"/f"identity-{index}.txt"
            subprocess.run([str(keygen),"-o",str(path)],check=True,capture_output=True)
            public=subprocess.run([str(keygen),"-y",str(path)],check=True,capture_output=True,text=True).stdout.strip()
            cls.identities.append(path);cls.recipients.append(public)
        cls.public=cls.root/"recipients.txt";cls.public.write_text("\n".join(cls.recipients[:2])+"\n",encoding="utf-8")
        cls.plain=cls.root/"synthetic-data.bin";cls.plain.write_bytes(MARKER*2000)

    def test_roundtrip_both_primary_and_escrow_keys_and_ciphertext_has_no_marker(self):
        encrypted=self.root/"archives"/"roundtrip.age";encrypt(AGE,self.plain,self.public,encrypted)
        self.assertTrue(encrypted.read_bytes().startswith(b"age-encryption.org/v1"));self.assertNotIn(MARKER,encrypted.read_bytes())
        for index in (0,1):
            restored=self.root/"restored"/f"roundtrip-{index}.bin";decrypt(AGE,encrypted,self.identities[index],restored)
            self.assertEqual(self.plain.read_bytes(),restored.read_bytes())

    def test_wrong_key_and_tamper_never_publish_plaintext_or_log_markers(self):
        encrypted=self.root/"archives"/"negative.age";encrypt(AGE,self.plain,self.public,encrypted)
        for index in (0,1):
            source=encrypted
            if index:
                data=bytearray(encrypted.read_bytes());data[-1]^=1
                source=self.root/"archives"/"tampered.age";source.write_bytes(data)
            restored=self.root/"restored"/f"negative-{index}.bin"
            out,err=io.StringIO(),io.StringIO()
            with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err),self.assertRaises(ValueError) as error:
                decrypt(AGE,source,self.identities[2] if index==0 else self.identities[0],restored)
            self.assertFalse(restored.exists());self.assertNotIn(MARKER.decode(),str(error.exception)+out.getvalue()+err.getvalue())

    def test_no_overwrite_or_private_key_as_recipient(self):
        encrypted=self.root/"archives"/"no-overwrite.age";encrypted.write_bytes(b"original-artifact")
        with self.assertRaises(ValueError):encrypt(AGE,self.plain,self.public,encrypted)
        self.assertEqual(b"original-artifact",encrypted.read_bytes())
        with self.assertRaises(ValueError):encrypt(AGE,self.plain,self.identities[0],self.root/"archives"/"invalid.age")


if __name__=="__main__":unittest.main()
