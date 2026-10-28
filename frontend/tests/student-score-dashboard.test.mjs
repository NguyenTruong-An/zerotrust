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

// In-memory component tests: no real browser, credentials or HTTP calls.
const dom = new JSDOM('<!doctype html><body></body>', { url: 'https://portal.test/' });
Object.assign(globalThis, { window: dom.window, document: dom.window.document,
  HTMLElement: dom.window.HTMLElement, IS_REACT_ACT_ENVIRONMENT: true });
Object.defineProperty(globalThis, 'navigator', { value: dom.window.navigator, configurable: true });
const { createRoot } = await import('react-dom/client');
const nodeRequire = createRequire(import.meta.url);
const frontend = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
after(() => dom.window.close());

// Compile the actual TSX and local helpers with the existing TypeScript dependency.
// Only the API boundary and account-security URL are substituted, never React hooks.
function loadComponent(portalRequest) {
  class AuthenticationExpiredError extends Error {}
  const cache = new Map();
  function load(filename) {
    if (cache.has(filename)) return cache.get(filename).exports;
    const compiled = ts.transpileModule(readFileSync(filename, 'utf8'), {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020,
        jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true }, fileName: filename,
    }).outputText;
    const compiledModule = { exports: {} };
    cache.set(filename, compiledModule);
    function dependency(specifier) {
      if (specifier === '../lib/api' || specifier === './api') return { AuthenticationExpiredError };
      if (specifier === '../lib/keycloak') return { accountSecurityUrl: () => 'https://portal.test/account' };
      if (specifier === '../lib/admin-api') {
        return { ...load(path.join(frontend, 'lib/admin-api.ts')), portalRequest };
      }
      if (specifier.startsWith('.')) return load(path.resolve(path.dirname(filename), `${specifier}.ts`));
      return nodeRequire(specifier);
    }
    const run = vm.runInThisContext(`(function(module, exports, require) { ${compiled}\n})`, { filename });
    run(compiledModule, compiledModule.exports, dependency);
    return compiledModule.exports;
  }
  return load(path.join(frontend, 'components/student-score-dashboard.tsx')).StudentScoreDashboard;
}

function scorePage(page = 0) {
  return { content: [{ id: `score-${page}`, studentId: 'synthetic-student',
    subjectCode: 'TEST', subjectName: `Synthetic subject ${page}`, academicYear: '2025-2026',
    semester: 1, attendanceScore: 8, midtermScore: 8, finalScore: 8, totalScore: 8, grade: 'B+' }],
  page, size: 10, totalElements: 20, totalPages: 2, first: page === 0, last: page === 1 };
}

async function fixture(t) {
  const calls = [];
  const scores = [];
  let nextResult;
  let authExpired = 0;
  function portalRequest(url, init = {}) {
    const parsed = new URL(url, 'https://portal.test');
    calls.push({ path: parsed.pathname, method: init.method ?? 'GET' });
    if (parsed.pathname === '/api/students/me/scores') {
      scores.push({ params: parsed.searchParams, signal: init.signal });
      const pending = nextResult;
      nextResult = undefined;
      return typeof pending === 'function' ? pending()
        : pending ?? Promise.resolve(scorePage(Number(parsed.searchParams.get('page'))));
    }
    if (parsed.pathname === '/api/users/me' || parsed.pathname === '/api/students/me') {
      return Promise.resolve({ id: 'synthetic-student', username: 'synthetic-student',
        firstName: 'Synthetic', lastName: 'Student', studentCode: 'TEST', dateOfBirth: '2000-01-01',
        gender: 'OTHER', classCode: 'TEST', className: 'Test class', email: 'student@example.invalid' });
    }
    if (parsed.pathname === '/api/students/me/scores/summary') {
      return Promise.resolve({ totalSubjects: 20, completedSubjects: 20, passedSubjects: 20,
        failedSubjects: 0, averageScore: 8, highestScore: 8, latestSemester: 1, latestAcademicYear: '2025-2026' });
    }
    assert.fail(`Unexpected request: ${parsed.pathname}`);
  }
  const Component = loadComponent(portalRequest);
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  t.after(async () => { await act(async () => root.unmount()); container.remove(); });
  await act(async () => root.render(React.createElement(Component, {
    username: 'synthetic-student', onLogout: () => {}, onAuthenticationExpired: () => { authExpired++; },
  })));
  const reset = () => container.querySelector('button.filter-secondary');
  const loaded = () => {
    assert.equal(reset().disabled, false, 'Loading must finish');
    assert.equal(container.querySelectorAll('tr.score-skeleton-row').length, 0);
    assert.match(container.querySelector('table tbody').textContent, /Synthetic subject/);
    assert.ok(calls.every(c => c.method === 'GET' && !c.path.startsWith('/api/admin')));
    assert.equal(calls.filter(c => c.path !== '/api/students/me/scores').length, 3,
      'Reset must not reload identity or summary');
    assert.equal(authExpired, 0);
  };
  return { container, calls, scores, reset, loaded,
    clickReset: () => act(async () => reset().click()),
    next: promise => { nextResult = promise; } };
}

test('Reset at initial defaults reloads once and leaves the table visible', async t => {
  const f = await fixture(t);
  assert.equal(f.scores.length, 1);
  await f.clickReset();
  assert.equal(f.scores.length, 2);
  f.loaded();
});

test('Reset clears applied filter values and restores default query in one request', async t => {
  const f = await fixture(t);
  const semester = f.container.querySelector('select');
  await act(async () => { semester.value = '1'; semester.dispatchEvent(new window.Event('change', { bubbles: true })); });
  await act(async () => f.container.querySelector('form').dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true })));
  assert.equal(f.scores.at(-1).params.get('semester'), '1');
  const count = f.scores.length;
  await f.clickReset();
  assert.equal(f.scores.length, count + 1);
  assert.equal(f.scores.at(-1).params.has('semester'), false);
  assert.equal(semester.value, '');
  f.loaded();
});

test('Repeated settled Reset clicks each finish without duplicate effect requests', async t => {
  const f = await fixture(t);
  for (let index = 0; index < 3; index++) {
    const count = f.scores.length;
    await f.clickReset();
    assert.equal(f.scores.length, count + 1);
    f.loaded();
  }
});

test('Reset from a later page requests page zero once', async t => {
  const f = await fixture(t);
  await act(async () => f.container.querySelector('button[aria-label="Trang sau"]').click());
  assert.equal(f.scores.at(-1).params.get('page'), '1');
  const count = f.scores.length;
  await f.clickReset();
  assert.equal(f.scores.length, count + 1);
  assert.equal(f.scores.at(-1).params.get('page'), '0');
  f.loaded();
});

test('Pending request disables Reset and ignores repeated clicks until completion', async t => {
  const f = await fixture(t);
  let resolve;
  f.next(new Promise(done => { resolve = done; }));
  const count = f.scores.length;
  await f.clickReset();
  assert.equal(f.scores.length, count + 1);
  assert.equal(f.reset().disabled, true);
  await act(async () => { f.reset().click(); f.reset().click(); });
  assert.equal(f.scores.length, count + 1);
  await act(async () => resolve(scorePage()));
  f.loaded();
});

test('Reset retries a failed default query and clears loading and error', async t => {
  const f = await fixture(t);
  f.next(() => Promise.reject(new Error('Synthetic request failure')));
  const initialCount = f.scores.length;
  await f.clickReset();
  assert.equal(f.scores.length, initialCount + 1);
  assert.match(f.container.querySelector('[role="alert"]').textContent, /Synthetic request failure/);
  const count = f.scores.length;
  await f.clickReset();
  assert.equal(f.scores.length, count + 1);
  assert.equal(f.container.querySelector('[role="alert"]'), null);
  f.loaded();
});
