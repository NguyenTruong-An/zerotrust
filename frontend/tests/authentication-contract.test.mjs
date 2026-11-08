import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';

// Execute the actual TS modules; only adapter/network boundaries are synthetic.
function load(relative, dependencies, globals = {}) {
  const source = readFileSync(new URL(relative, import.meta.url), 'utf8');
  const js = ts.transpileModule(source, { compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true,
  } }).outputText;
  const compiledModule = { exports: {} };
  const context = vm.createContext({ module: compiledModule, exports: compiledModule.exports,
    require(name) { assert.ok(name in dependencies); return dependencies[name]; },
    Headers, process: { env: {} }, ...globals });
  new vm.Script(js, { filename: relative }).runInContext(context);
  return compiledModule.exports;
}

function api(options = {}) {
  const calls = { refresh: [], requests: [], clear: 0 };
  const keycloak = { authenticated: true, token: 'synthetic-current-access',
    updateToken(validity) { calls.refresh.push(validity); return options.refresh?.(keycloak, validity) ?? Promise.resolve(false); },
    clearToken() { calls.clear++; this.authenticated = false; this.token = undefined; }, ...options.keycloak };
  const exported = load('../lib/api.ts', { './keycloak': { getKeycloak: () => keycloak } }, {
    fetch: async (url, init) => {
      calls.requests.push({ url, init });
      return { status: options.statuses?.[calls.requests.length - 1] ?? 200 };
    },
  });
  return { ...exported, keycloak, calls };
}

test('adapter receives PKCE S256 and check-sso once without a browser client secret', async () => {
  const calls = { construct: [], init: [] };
  class Adapter {
    constructor(config) { calls.construct.push(config); }
    init(config) { calls.init.push(config); return Promise.resolve(false); }
  }
  const keycloak = load('../lib/keycloak.ts', { 'keycloak-js': Adapter }, {
    window: { location: { origin: 'https://portal.test' } },
    localStorage: { setItem() { throw new Error('persistent token storage forbidden'); } },
    sessionStorage: { setItem() { throw new Error('persistent token storage forbidden'); } },
  });
  await Promise.all([keycloak.initializeKeycloak(), keycloak.initializeKeycloak()]);
  assert.equal(calls.construct.length, 1); assert.equal(calls.init.length, 1);
  assert.equal(calls.init[0].pkceMethod, 'S256'); assert.equal(calls.init[0].onLoad, 'check-sso');
  assert.equal(calls.init[0].silentCheckSsoRedirectUri, 'https://portal.test/silent-check-sso.html');
  assert.equal('clientSecret' in calls.construct[0], false);
});

test('API overwrites supplied authorization with refreshed access token and omits cookies', async () => {
  const f = api({ refresh(keycloak) { keycloak.token = 'synthetic-refreshed-access'; return Promise.resolve(true); } });
  await f.apiFetch('/api/students/me', { headers: { Authorization: 'untrusted-token' } });
  assert.deepEqual(f.calls.refresh, [30]);
  assert.equal(f.calls.requests[0].init.headers.get('Authorization'), 'Bearer synthetic-refreshed-access');
  assert.equal(f.calls.requests[0].init.credentials, 'omit');
});

test('401 forces one refresh and uses the new token on one retry', async () => {
  const f = api({ statuses: [401, 200], refresh(keycloak, validity) {
    if (validity === -1) keycloak.token = 'synthetic-retry-access'; return Promise.resolve(true);
  } });
  assert.equal((await f.apiFetch('/api/students/me')).status, 200);
  assert.deepEqual(f.calls.refresh, [30, -1]); assert.equal(f.calls.requests.length, 2);
  assert.equal(f.calls.requests[1].init.headers.get('Authorization'), 'Bearer synthetic-retry-access');
});

test('a second 401 does not start an unbounded refresh or request loop', async () => {
  const f = api({ statuses: [401, 401] });
  assert.equal((await f.apiFetch('/api/students/me')).status, 401);
  assert.deepEqual(f.calls.refresh, [30, -1]); assert.equal(f.calls.requests.length, 2);
});

test('failed refresh clears local tokens and makes no API request', async () => {
  const f = api({ refresh() { return Promise.reject(new Error('synthetic-secret-must-not-escape')); } });
  await assert.rejects(f.apiFetch('/api/students/me'), error =>
    error.name === 'AuthenticationExpiredError' && !error.message.includes('synthetic-secret'));
  assert.equal(f.calls.clear, 1); assert.equal(f.calls.requests.length, 0);
});

test('unauthenticated session cannot send a bearer request', async () => {
  const f = api({ keycloak: { authenticated: false } });
  await assert.rejects(f.apiFetch('/api/students/me'), { name: 'AuthenticationExpiredError' });
  assert.equal(f.calls.requests.length, 0); assert.equal(f.calls.refresh.length, 0);
});

test('concurrent API calls share the in-flight refresh', async () => {
  let complete;
  const pending = new Promise(resolve => { complete = resolve; });
  const f = api({ refresh() { return pending; } });
  const first = f.apiFetch('/api/students/me'); const second = f.apiFetch('/api/students/me/scores');
  assert.equal(f.calls.refresh.length, 1); assert.equal(f.calls.requests.length, 0);
  complete(true); await Promise.all([first, second]); assert.equal(f.calls.requests.length, 2);
});
