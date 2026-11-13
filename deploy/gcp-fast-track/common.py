"""Shared configuration for the GCP fast-track profile (fresh V1->V9 strict install)."""
import hashlib, ipaddress, json, os
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def sha_file(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def config(path):
    """mode=rehearsal: local disposable lane, synthetic CA at the edge, loopback only.
    mode=gcp: Linux VM, Let's Encrypt edge certificate, loopback until the owner opens 443."""
    c = json.loads(Path(path).read_text(encoding='utf-8'))
    need(c['mode'] in ('rehearsal', 'gcp'), 'MODE')
    ip = ipaddress.IPv4Address(c['public_ip'])
    need(ip.is_global, 'PUBLIC_IP_REQUIRED')
    c['portal_host'] = f'portal.{ip}.sslip.io'
    c['auth_host'] = f'auth.{ip}.sslip.io'
    c['portal_url'] = 'https://' + c['portal_host']
    c['auth_url'] = 'https://' + c['auth_host']
    c['issuer'] = c['auth_url'] + '/realms/DoAn'
    need(c['project'].startswith('zt-gcp-ft') and c['project'].replace('-', '').isalnum(), 'PROJECT_SCOPE')
    c['out'] = Path(c['out']) if Path(c['out']).is_absolute() else ROOT / c['out']
    c['state'] = c['out'] / 'private'
    c['out'].mkdir(parents=True, exist_ok=True)
    n = ipaddress.ip_network(c['subnet'])
    need(n.is_private and n.prefixlen == 27, 'SUBNET')
    # Explicit /27 blocks after the core block: no dependency on Docker's default address pools.
    c['recovery_subnet'] = str(ipaddress.ip_network((int(n.network_address) + 32, 27)))
    c['edge_subnet'] = str(ipaddress.ip_network((int(n.network_address) + 64, 27)))
    c['proxy_ip'] = str(n.network_address + 25)
    c['high_test_ip'] = str(n.network_address + 27)
    c['frontend_image'] = 'zt-gcp-ft/frontend:' + str(ip).replace('.', '-')
    return c
