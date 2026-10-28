"""Stage legacy TLS maintenance offline; never install files, restart or change trust stores.

Requires cryptography >= 44. Output must be a new directory under .local-legacy.
Review manifest.json and obtain runtime approval before installing any candidate.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID

PROJECT = 'zerotrust-legacy-integration-20261026'
PUBLIC_CDP = ('http://localhost:28445/ca.crl', 'http://crl:8080/ca.crl')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def public_distribution_points():
    # RFC 5280 section 4.2.1.13: alternative locations of the SAME complete CRL.
    return x509.CRLDistributionPoints([x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier(uri) for uri in PUBLIC_CDP],
        relative_name=None, reasons=None, crl_issuer=None)])


def validate_authority(ca, key, now):
    ca.verify_directly_issued_by(ca)
    require(ca.public_key().public_numbers() == key.public_key().public_numbers(), 'CA_KEY_MISMATCH')
    require(ca.not_valid_before_utc <= now < ca.not_valid_after_utc, 'CA_NOT_CURRENT')
    require(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, 'CA_REQUIRED')
    usage = ca.extensions.get_extension_for_class(x509.KeyUsage).value
    require(usage.key_cert_sign and usage.crl_sign, 'CA_SIGNING_USAGE_REQUIRED')


def renew_crl(ca, key, previous, now):
    validate_authority(ca, key, now)
    require(previous.issuer == ca.subject and previous.is_signature_valid(ca.public_key()), 'OLD_CRL_INVALID')
    require(previous.last_update_utc <= now, 'CRL_CLOCK_REGRESSION')
    require(not any(isinstance(e.value, x509.DeltaCRLIndicator) for e in previous.extensions), 'COMPLETE_CRL_REQUIRED')
    prior_number = next((e.value.crl_number for e in previous.extensions
                         if isinstance(e.value, x509.CRLNumber)), 0)
    builder = (x509.CertificateRevocationListBuilder().issuer_name(ca.subject)
               .last_update(max(previous.last_update_utc, now - dt.timedelta(minutes=1)))
               .next_update(min(now + dt.timedelta(days=7), ca.not_valid_after_utc)))
    for entry in previous:
        builder = builder.add_revoked_certificate(entry)
    for extension in previous.extensions:
        if not isinstance(extension.value, (x509.CRLNumber, x509.AuthorityKeyIdentifier)):
            builder = builder.add_extension(extension.value, extension.critical)
    return (builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
            .add_extension(x509.CRLNumber(max(prior_number + 1, int(now.timestamp()))), False)
            .sign(key, hashes.SHA256()))


def reissue_public_certificate(ca, ca_key, cert, leaf_key, crl, now):
    validate_authority(ca, ca_key, now)
    cert.verify_directly_issued_by(ca)
    require(cert.not_valid_before_utc <= now < cert.not_valid_after_utc, 'LEAF_NOT_CURRENT')
    require(not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, 'LEAF_REQUIRED')
    require(cert.public_key().public_numbers() == leaf_key.public_key().public_numbers(), 'LEAF_KEY_MISMATCH')
    require(crl.get_revoked_certificate_by_serial_number(cert.serial_number) is None, 'REVOKED_LEAF')
    builder = (x509.CertificateBuilder().subject_name(cert.subject).issuer_name(ca.subject)
               .public_key(cert.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(cert.not_valid_before_utc).not_valid_after(cert.not_valid_after_utc))
    for extension in cert.extensions:
        if not isinstance(extension.value, x509.CRLDistributionPoints):
            builder = builder.add_extension(extension.value, extension.critical)
    return builder.add_extension(public_distribution_points(), False).sign(ca_key, hashes.SHA256())


def check(state):
    """Read public files only. Exit nonzero when renewal is due within two days."""
    require(json.loads((state / 'owner.json').read_text())['owner'] == PROJECT, 'STATE_OWNER_MISMATCH')
    now = dt.datetime.now(dt.timezone.utc)
    ca = x509.load_pem_x509_certificate((state / 'public-ca/ca.crt').read_bytes())
    ca.verify_directly_issued_by(ca)
    require(ca.not_valid_before_utc <= now < ca.not_valid_after_utc, 'CA_NOT_CURRENT')
    crl = x509.load_der_x509_crl((state / 'public-ca/ca.crl').read_bytes())
    require(crl.issuer == ca.subject and crl.is_signature_valid(ca.public_key()), 'CRL_INVALID')
    require(crl.last_update_utc <= now < crl.next_update_utc, 'CRL_NOT_CURRENT')
    renewal_due = crl.next_update_utc <= now + dt.timedelta(days=2)
    leaves = {}
    for role in ('gateway', 'keycloak', 'backend', 'risk'):
        cert = x509.load_pem_x509_certificate((state / role / 'server.crt').read_bytes())
        cert.verify_directly_issued_by(ca)
        require(cert.not_valid_before_utc <= now < cert.not_valid_after_utc, 'LEAF_NOT_CURRENT_' + role)
        require(crl.get_revoked_certificate_by_serial_number(cert.serial_number) is None, 'LEAF_REVOKED_' + role)
        require(ExtendedKeyUsageOID.SERVER_AUTH in cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage).value, 'SERVER_AUTH_REQUIRED_' + role)
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        require({role, 'localhost'} <= set(sans.get_values_for_type(x509.DNSName)), 'SAN_REQUIRED_' + role)
        if role in ('gateway', 'keycloak'):
            points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
            require(any(point.full_name and [name.value for name in point.full_name] == list(PUBLIC_CDP)
                        for point in points), 'WINDOWS_AND_DOCKER_CDP_REQUIRED_' + role)
        leaves[role] = cert.not_valid_after_utc.isoformat()
        renewal_due |= cert.not_valid_after_utc <= now + dt.timedelta(days=2)
    print(json.dumps({'status': 'RENEWAL_DUE' if renewal_due else 'PASS',
                      'crl_next_update': crl.next_update_utc.isoformat(), 'leaf_expiry': leaves,
                      'writes': 0}, indent=2))
    return 2 if renewal_due else 0


def stage(state, output, reissue=False):
    state, output = state.resolve(), output.resolve()
    private_root = Path(__file__).resolve().parents[2] / '.local-legacy'
    require(output.is_relative_to(private_root.resolve()), 'OUTPUT_MUST_BE_GIT_IGNORED_LOCAL_LEGACY')
    require(not output.exists(), 'OUTPUT_ALREADY_EXISTS')
    require(not output.is_relative_to(state), 'OUTPUT_MUST_NOT_BE_LIVE_STATE')
    require(json.loads((state / 'owner.json').read_text())['owner'] == PROJECT, 'STATE_OWNER_MISMATCH')
    inputs = {}

    def read(relative):
        data = (state / relative).read_bytes()
        inputs[relative] = hashlib.sha256(data).hexdigest()
        return data

    now = dt.datetime.now(dt.timezone.utc)
    ca = x509.load_pem_x509_certificate(read('public-ca/ca.crt'))
    ca_key = serialization.load_pem_private_key(read('authority/ca.key'), None)
    old_crl = x509.load_der_x509_crl(read('public-ca/ca.crl'))
    crl = renew_crl(ca, ca_key, old_crl, now)
    candidates = {'public-ca/ca.crl': crl.public_bytes(serialization.Encoding.DER)}
    if reissue:
        for role in ('gateway', 'keycloak'):
            cert = x509.load_pem_x509_certificate(read(role + '/server.crt'))
            leaf_key = serialization.load_pem_private_key(read(role + '/server.key'), None)
            password = read(role + '/store-password')
            key, stored_cert, chain = pkcs12.load_key_and_certificates(read(role + '/server.p12'), password)
            require(stored_cert == cert and key.public_key().public_numbers() == cert.public_key().public_numbers()
                    and ca in (chain or []), 'EXISTING_STORE_MISMATCH')
            replacement = reissue_public_certificate(ca, ca_key, cert, leaf_key, old_crl, now)
            candidates[role + '/server.crt'] = replacement.public_bytes(serialization.Encoding.PEM)
            candidates[role + '/server.p12'] = pkcs12.serialize_key_and_certificates(
                b'server', leaf_key, replacement, [ca], serialization.BestAvailableEncryption(password))
    output.mkdir(parents=True, mode=0o700)
    changes = {}
    for relative, data in candidates.items():
        old = read(relative)
        for directory, value in [('before', old), ('candidate', data)]:
            destination = output / directory / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            destination.write_bytes(value)
            destination.chmod(0o600)
        changes[relative] = {'before': hashlib.sha256(old).hexdigest(), 'candidate': hashlib.sha256(data).hexdigest()}
    manifest = {'project': PROJECT, 'created': now.isoformat(), 'state': str(state),
                'inputs_sha256': inputs, 'changes': changes, 'public_cdp': PUBLIC_CDP,
                'crl_next_update': crl.next_update_utc.isoformat(), 'revoked_entries_preserved': len(old_crl),
                'runtime_files_installed': 0, 'containers_restarted': 0}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps({'staged_files': list(changes), 'crl_next_update': manifest['crl_next_update'],
                      'runtime_files_installed': 0, 'containers_restarted': 0}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check', action='store_true', help='Read public files only; no signing or writes')
    parser.add_argument('--reissue-public-certificates', action='store_true')
    args = parser.parse_args()
    if args.check:
        require(args.output is None and not args.reissue_public_certificates, 'CHECK_IS_READ_ONLY')
        raise SystemExit(check(args.state))
    require(args.output is not None, 'OUTPUT_REQUIRED_FOR_STAGING')
    stage(args.state, args.output, args.reissue_public_certificates)
