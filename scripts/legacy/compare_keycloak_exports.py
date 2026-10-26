"""Compare official CLI exports before any approved integration-only endpoint changes."""
import argparse
import copy
import hashlib
import json
from pathlib import Path


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def collection_order(value):
    # Keycloak collection iteration differs across H2/MySQL. Execution priority remains a compared field.
    if isinstance(value, dict):
        return {k: collection_order(v) for k, v in value.items()}
    if isinstance(value, list):
        return sorted((collection_order(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    return value


def model(realm):
    users = {}
    for user in realm.get('users', []):
        credentials = []
        for credential in user.get('credentials', []):
            credentials.append({'type': credential['type'],
                                'data': json.loads(credential.get('credentialData', '{}')),
                                'secret': json.loads(credential.get('secretData', '{}')),
                                'userLabel': credential.get('userLabel')})
        users[user['id']] = {
            'username': user['username'], 'enabled': user.get('enabled'),
            'email': user.get('email'), 'realmRoles': sorted(user.get('realmRoles', [])),
            'clientRoles': {k: sorted(v) for k, v in user.get('clientRoles', {}).items()},
            'groups': sorted(user.get('groups', [])), 'serviceAccountClientId': user.get('serviceAccountClientId'),
            'requiredActions': sorted(user.get('requiredActions', [])),
            'credentials_sha256': sorted(digest(c) for c in credentials)}
    fields = ['id', 'realm', 'browserFlow', 'directGrantFlow', 'requiredActions',
              'authenticationFlows', 'authenticatorConfig', 'groups', 'roles', 'components']
    selected = {k: realm.get(k) for k in fields}
    # Canonical order only; no ID/key/secret remapping or unsupported database conversion.
    for key in ['requiredActions', 'authenticationFlows', 'authenticatorConfig', 'groups']:
        if isinstance(selected[key], list):
            selected[key] = sorted(selected[key], key=lambda x: x.get('id', x.get('alias', x.get('name', ''))))
    selected['users'] = users
    selected['clients'] = {c['clientId']: c for c in realm.get('clients', [])}
    return {k: digest(collection_order(v)) for k, v in selected.items()}


def client_contracts(source, target):
    """Compare effective 26.7 defaults; keep every existing secret, ID and grant strict.

    Keycloak RepresentationToModel/MigrationUtils and OIDCAdvancedConfigWrapper
    materialize these defaults during CLI import. No database is changed here.
    """
    before = {c['clientId']: copy.deepcopy(c) for c in source.get('clients', [])}
    after = {c['clientId']: copy.deepcopy(c) for c in target.get('clients', [])}
    generated_bearer_secrets = []
    for client_id, original in before.items():
        if client_id not in after:
            continue
        imported = after[client_id]
        for client in (original, imported):
            client.setdefault('attributes', {}).setdefault('post.logout.redirect.uris', '+')
            client.setdefault('protocol', 'openid-connect')
            for mapper in client.get('protocolMappers', []):
                config = mapper.get('config', {})
                if 'userinfo.token.claim' not in config and 'id.token.claim' in config:
                    config['userinfo.token.claim'] = config['id.token.claim']
        # Only absent, unusable credentials on these built-in bearer-only clients.
        # Existing application/service credentials always remain part of comparison.
        if (client_id in {'broker', 'realm-management', 'master-realm', 'DoAn-realm'}
                and 'secret' not in original and 'secret' in imported
                and all(c.get('bearerOnly') is True for c in (original, imported))
                and all(c.get('serviceAccountsEnabled') is False for c in (original, imported))
                and all(c.get('directAccessGrantsEnabled') is False for c in (original, imported))
                and all(c.get('publicClient') is False for c in (original, imported))
                and 'client.secret.creation.time' not in original['attributes']):
            imported.pop('secret')
            imported['attributes'].pop('client.secret.creation.time', None)
            generated_bearer_secrets.append(client_id)
    return (digest(collection_order(before)) == digest(collection_order(after)),
            generated_bearer_secrets)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('source')
    parser.add_argument('target')
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    def load(folder):
        return {r['realm']: r for f in Path(folder).glob('*-realm.json')
                for r in [json.loads(f.read_text(encoding='utf-8'))]}
    source, target = load(args.source), load(args.target)
    result = {'realm_names_equal': set(source) == set(target), 'realms': {},
              'raw_clients_equal': {}, 'CLI_generated_builtin_bearer_secrets': {}}
    for name, value in source.items():
        if name not in target:
            result['realms'][name] = {'missing': True}; continue
        a, b = model(value), model(target[name])
        result['realms'][name] = {key: a[key] == b[key] for key in a}
        result['raw_clients_equal'][name] = result['realms'][name]['clients']
        same, generated = client_contracts(value, target[name])
        result['realms'][name]['clients'] = same
        result['CLI_generated_builtin_bearer_secrets'][name] = generated
    result['PASS'] = result['realm_names_equal'] and all(
        all(checks.values()) and not checks.get('missing') for checks in result['realms'].values())
    Path(args.report).write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    if not result['PASS']:
        raise SystemExit('KEYCLOAK_IMPORT_INVARIANT_DRIFT; stop; no direct SQL repair')


if __name__ == '__main__':
    main()
