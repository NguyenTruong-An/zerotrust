import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { after, test } from 'node:test';
import React, { act } from 'react';
import ts from 'typescript';
import { JSDOM } from 'jsdom';

// Actual PortalRoute/hooks; only navigation, Keycloak and business-view boundaries are mocked.
const dom = new JSDOM('<!doctype html><body></body>', { url: 'https://portal.test/' });
Object.assign(globalThis, { window: dom.window, document: dom.window.document,
  HTMLElement: dom.window.HTMLElement, IS_REACT_ACT_ENVIRONMENT: true });
Object.defineProperty(globalThis, 'navigator', { value: dom.window.navigator, configurable: true });
const { createRoot } = await import('react-dom/client');
const nodeRequire = createRequire(import.meta.url);
const frontend = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
after(() => dom.window.close());

async function fixture(t, options = {}) {
  const calls = { logout: [], clear: 0, navigation: [], router: [], admin: 0, student: 0 };
  let renderedProps;
  const keycloak = { authenticated: true, idToken: 'synthetic-opaque-id-hint', subject: 'synthetic-subject',
    tokenParsed: { preferred_username: 'synthetic-user' }, realmAccess: { roles: options.roles ?? ['STUDENT'] },
    clearToken() { calls.clear++; this.authenticated = false; this.idToken = undefined; this.onAuthLogout?.(); },
    logout(config) { calls.logout.push({ config, idHintPresent: Boolean(this.idToken) }); return options.logout?.() ?? Promise.resolve(); },
    login() { return Promise.resolve(); } };
  function businessView(kind, props) {
    calls[kind]++; renderedProps = props;
    return React.createElement('section', { 'data-view': kind },
      React.createElement('button', { onClick: props.onLogout }, 'Logout fixture'));
  }
  class AuthenticationExpiredError extends Error {}
  const source = readFileSync(path.join(frontend, 'components/portal-route.tsx'), 'utf8');
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2020, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true } }).outputText;
  function dependency(name) {
    if (name === 'next/navigation') return { usePathname: () => options.path ?? '/student/scores',
      useRouter: () => ({ replace: route => calls.router.push(route) }) };
    if (name === './admin-portal') return { ADMIN_VIEW_PATHS: { overview: '/admin' }, AdminPortal: p => businessView('admin', p) };
    if (name === './student-score-dashboard') return { StudentScoreDashboard: p => businessView('student', p) };
    if (name === '../lib/api') return { AuthenticationExpiredError };
    if (name === '../lib/keycloak') return { getKeycloak: () => keycloak, initializeKeycloak: () => Promise.resolve(true),
      appRedirectUri: () => 'https://portal.test/' };
    return nodeRequire(name);
  }
  const fakeWindow = { location: { replace: url => calls.navigation.push(url), reload: () => {} } };
  const compiledModule = { exports: {} };
  vm.runInThisContext(`(function(module,exports,require,window){${compiled}\n})`, { filename: 'portal-route-test.cjs' })(compiledModule, compiledModule.exports, dependency, fakeWindow);
  const container = document.createElement('div'); document.body.append(container);
  const root = createRoot(container);
  t.after(async () => { await act(async () => root.unmount()); container.remove(); });
  await act(async () => root.render(React.createElement(compiledModule.exports.PortalRoute, { area: options.area ?? 'student' })));
  return { calls, keycloak, container, props: () => renderedProps,
    logout: () => act(async () => container.querySelector('button').click()) };
}

test('STUDENT on an ADMIN route is redirected without rendering the ADMIN view', async t => {
  const f = await fixture(t, { area: 'admin', path: '/admin' });
  assert.equal(f.calls.admin, 0); assert.equal(f.calls.student, 0);
  assert.deepEqual(f.calls.router, ['/student/scores']);
});

test('An ADMIN-only identity can render the ADMIN view', async t => {
  const f = await fixture(t, { roles: ['ADMIN'], area: 'admin', path: '/admin' });
  assert.ok(f.container.querySelector('[data-view="admin"]'));
  assert.equal(f.calls.student, 0);
});

test('An identity without a business role cannot render business views', async t => {
  const f = await fixture(t, { roles: [] });
  assert.equal(f.calls.admin + f.calls.student, 0);
  assert.match(f.container.textContent, /Chưa có quyền truy cập/);
});

test('Session expiry outside logout still clears the token and redirects to login', async t => {
  const f = await fixture(t);
  await act(async () => f.props().onAuthenticationExpired());
  assert.equal(f.calls.clear, 1);
  assert.ok(f.calls.navigation.length > 0);
  assert.ok(f.calls.navigation.every(url => url === '/'));
  assert.equal(f.container.querySelector('[data-view]'), null);
});

test('Logout invokes Keycloak with its ID hint intact and does not claim completion on promise resolution', async t => {
  const f = await fixture(t); await f.logout();
  assert.deepEqual(f.calls.logout, [{ config: { redirectUri: 'https://portal.test/' }, idHintPresent: true }]);
  assert.equal(f.calls.clear, 0); assert.deepEqual(f.calls.navigation, []);
  assert.equal(f.container.querySelector('[data-view]'), null);
});

test('A refresh-error callback during logout cannot replace the IdP logout navigation', async t => {
  const f = await fixture(t); await f.logout();
  await act(async () => f.keycloak.onAuthRefreshError?.());
  assert.deepEqual(f.calls.navigation, [], 'Do not cancel end-session navigation with a root redirect');
});

test('A rejected logout is visible and retryable instead of silently returning to check-sso', async t => {
  let attempts = 0;
  const f = await fixture(t, { logout: () => ++attempts === 1 ? Promise.reject(new Error('synthetic-network-failure')) : Promise.resolve() });
  await f.logout();
  assert.deepEqual(f.calls.navigation, [], 'A failed server logout must not look like a successful local redirect');
  assert.match(f.container.textContent, /Đăng xuất chưa hoàn tất/);
  assert.equal(f.container.querySelector('[data-view]'), null);
  assert.doesNotMatch(f.container.textContent, /synthetic-network-failure/);
  await act(async () => f.keycloak.onAuthLogout?.());
  assert.deepEqual(f.calls.navigation, []);
  assert.equal(f.calls.clear, 0, 'Keep the ID hint available for the explicit end-session retry');
  await act(async () => f.container.querySelector('button').click());
  assert.equal(f.calls.logout.length, 2);
});

test('A stale business request cannot redirect or clear the logout context', async t => {
  const f = await fixture(t); const props = f.props(); await f.logout();
  await act(async () => props.onAuthenticationExpired());
  assert.equal(f.calls.clear, 0); assert.deepEqual(f.calls.navigation, []);
});

test('Duplicate logout callbacks initiate only one end-session attempt', async t => {
  const f = await fixture(t); const props = f.props();
  await act(async () => { props.onLogout(); props.onLogout(); });
  assert.equal(f.calls.logout.length, 1);
});
