"""Run a sealed D-10 helper (native_admin / native_acceptance) with only its two origins rebound.

The sealed files are never modified; this replaces the full-function origins in memory with the
GCP sslip.io origins and executes the same code. Used inside the acceptance helper container.
"""
import os, sys

SEALED = {'native_admin': 1, 'native_acceptance': 4}
PORTAL_OLD, AUTH_OLD = 'https://portal.full-function.test:39443', 'https://auth.full-function.test:39443'


def main():
    which = sys.argv[1]
    if which not in SEALED:
        raise SystemExit('ADAPT_SCOPE')
    portal, auth = os.environ['GCP_PORTAL'], os.environ['GCP_AUTH']
    if not (portal.startswith('https://portal.') and auth.startswith('https://auth.') and portal.endswith('.sslip.io') and auth.endswith('.sslip.io')):
        raise SystemExit('ADAPT_ORIGIN')
    path = '/scripts/' + which + '.py'
    source = open(path, encoding='utf-8').read()
    found = source.count(PORTAL_OLD) + source.count(AUTH_OLD)
    if found < SEALED[which]:
        raise SystemExit('ADAPT_ORIGIN_COUNT_' + str(found))
    source = source.replace(PORTAL_OLD, portal).replace(AUTH_OLD, auth)
    if 'full-function.test:39443' in source:
        raise SystemExit('ADAPT_RESIDUAL_ORIGIN')
    sys.path.insert(0, '/scripts')
    sys.argv = [path] + sys.argv[2:]
    exec(compile(source, path, 'exec'), {'__name__': '__main__', '__file__': path})


if __name__ == '__main__':
    main()
