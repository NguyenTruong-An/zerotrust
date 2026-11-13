"""Offline sslip.io configuration. Does not invoke Docker, ACME or Google Cloud."""
import argparse
import ipaddress
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def hosts(value):
    ip = ipaddress.IPv4Address(value)
    if not ip.is_global or ip.is_multicast:
        raise ValueError('A real public static IPv4 is required')
    return f'portal.{ip}.sslip.io', f'auth.{ip}.sslip.io'


def configuration(ip):
    portal, auth = hosts(ip)
    c = json.loads((HERE.parent/'rc/production.example.json').read_text())
    c.update(release='academic-gcp-rc1', portal_host=portal, auth_host=auth)
    return c


def acme_nginx(ip):
    portal, auth = hosts(ip)
    # A dedicated host NGINX process. No HTTPS/application upstream, including before issuance.
    return f'''pid /run/zerotrust-acme.pid;
error_log stderr warn;
events {{ worker_connections 128; }}
http {{
  access_log off;
  server_tokens off;
  client_max_body_size 1k;
  client_header_timeout 5s;
  client_body_timeout 5s;
  server {{ listen 0.0.0.0:80 default_server; server_name _; return 404; }}
  server {{
    listen 0.0.0.0:80;
    server_name {portal} {auth};
    location ~ ^/\\.well-known/acme-challenge/[A-Za-z0-9_-]+$ {{
      root /var/www/zerotrust-acme;
      default_type text/plain;
      limit_except GET {{ deny all; }}
      try_files $uri =404;
    }}
    location / {{ return 404; }}
  }}
}}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ip', required=True)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    c, nginx = configuration(a.ip), acme_nginx(a.ip)
    a.output.mkdir(parents=True, exist_ok=False)
    (a.output/'demo.json').write_text(json.dumps(c, indent=2)+'\n')
    (a.output/'nginx-acme.conf').write_text(nginx)
    print('Prepared hostname/ACME inputs only. D-04 and release gates remain pending.')


if __name__ == '__main__':
    main()
