import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { JSDOM } from 'jsdom';
import React, { act } from 'react';
import ts from 'typescript';

const origin = 'https://portal.example.invalid';
const authOrigin = 'https://auth.example.invalid';
const dom = new JSDOM('<!doctype html><body></body>', { url: origin });
Object.assign(globalThis, { window: dom.window, document: dom.window.document,
  HTMLElement: dom.window.HTMLElement, FormData: dom.window.FormData, IS_REACT_ACT_ENVIRONMENT: true });
window.scrollTo = () => {};
const { createRoot } = await import('react-dom/client');
const nodeRequire = createRequire(import.meta.url);
const frontend = fileURLToPath(new URL('../', import.meta.url));
const scripts = new Map();
after(() => dom.window.close());

const student = {
  id: '11111111-1111-4111-8111-111111111111', userId: '22222222-2222-4222-8222-222222222222',
  firstName: 'Demo', lastName: 'Student', studentCode: 'SYNTH-STUDENT', username: 'fixture-user',
  dateOfBirth: '2000-01-01', gender: 'OTHER', status: 'ACTIVE', email: 'fixture@example.invalid',
  classCode: 'SYNTH-CLASS', className: 'Synthetic class', phone: null, address: null,
};
const schoolClass = { id: '33333333-3333-4333-8333-333333333333', classCode: student.classCode,
  className: student.className, department: 'CNTT', courseYears: '2022-2027' };
const subject = { id: '44444444-4444-4444-8444-444444444444', subjectCode: 'SYNTH-SUBJECT',
  subjectName: 'Synthetic subject', credits: 3, description: 'Fixture only' };
const score = {
  id: '55555555-5555-4555-8555-555555555555', studentId: student.id, studentCode: student.studentCode,
  subjectId: subject.id, subjectCode: subject.subjectCode, subjectName: subject.subjectName,
  attendanceScore: 7, midtermScore: 7, finalScore: 7, totalScore: 8.4, grade: 'B+',
  semester: 2, academicYear: '2025-2026',
};
const studentUrl = `/api/admin/students/${student.id}`;
const sheetUrl = `/api/admin/subjects/${subject.id}/score-sheet`;
const resetUrl = `/api/admin/users/${student.userId}/mfa/reset`;
const token = 'SYNTHETIC_ACCESS_CANARY';
const page = content => ({ content, page: 0, size: 10, totalElements: content.length,
  totalPages: content.length ? 1 : 0, first: true, last: true });
const responses = {
  '/api/admin/students': page([student]),
  '/api/admin/student-classes': page([schoolClass]),
  '/api/admin/subjects': page([subject]),
  '/api/admin/users': [{ ...student, id: student.userId }],
  [studentUrl]: student,
  [`${studentUrl}/scores`]: page([score]),
  [sheetUrl]: page([{ ...student, ...score, scoreId: score.id }]),
  '/api/users/me': { ...student, id: student.userId },
  '/api/students/me': student,
  '/api/students/me/scores/summary': { totalSubjects: 1, completedSubjects: 1, passedSubjects: 1,
    failedSubjects: 0, averageScore: 8.4, highestScore: 8.4, latestSemester: 2, latestAcademicYear: '2025-2026' },
  '/api/students/me/scores': page([score]),
};

function fixture({ route = '/', roles = ['ADMIN'], authenticated = true,
  mode = 'public-demo', respond } = {}) {
  const calls = { requests: [], construct: [], init: [], login: [], logout: [], refresh: [], routes: [] };
  const router = { push: url => calls.routes.push(url), replace: url => calls.routes.push(url) };
  const env = { NEXT_PUBLIC_PORTAL_MODE: mode, NEXT_PUBLIC_API_BASE_URL: '',
    NEXT_PUBLIC_KEYCLOAK_URL: authOrigin, NEXT_PUBLIC_KEYCLOAK_REALM: 'synthetic-demo' };
  class Keycloak {
    authenticated = authenticated;
    subject = 'synthetic-subject';
    realmAccess = { roles };
    tokenParsed = { preferred_username: student.username };
    token = token;
    constructor(config) { calls.construct.push(config); }
    async init(config) { calls.init.push(config); return this.authenticated; }
    async updateToken(validity) { calls.refresh.push(validity); return false; }
    async login(config) { calls.login.push(config); }
    async logout(config) { calls.logout.push(config); }
    clearToken() { this.authenticated = false; this.token = undefined; }
  }
  const fetchFixture = async (url, init) => {
    const parsed = new URL(url, origin);
    const request = { url, parsed, init, method: init.method ?? 'GET' };
    calls.requests.push(request);
    assert.equal(parsed.origin, origin);
    const result = respond?.(request);
    if (result !== undefined) return result;
    if (request.method === 'POST' && parsed.pathname === resetUrl) return new Response(null, { status: 204 });
    assert.equal(request.method, 'GET');
    assert.ok(Object.hasOwn(responses, parsed.pathname), `Unexpected request: ${url}`);
    return Response.json({ data: responses[parsed.pathname] });
  };
  const cache = new Map();
  function load(filename) {
    if (cache.has(filename)) return cache.get(filename).exports;
    if (!scripts.has(filename)) {
      const compiled = ts.transpileModule(readFileSync(filename, 'utf8'), {
        fileName: filename,
        compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
          jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
      }).outputText;
      scripts.set(filename, vm.runInThisContext(
        `(function(module,exports,require,process,fetch){${compiled}\n})`, { filename }));
    }
    const compiledModule = { exports: {} };
    cache.set(filename, compiledModule);
    function dependency(name) {
      if (name === 'keycloak-js') return Keycloak;
      if (name === 'next/navigation') return { usePathname: () => route, useRouter: () => router };
      if (name === 'next/link') return function Link(props) { return React.createElement('a', props); };
      if (name.startsWith('.')) {
        const base = path.resolve(path.dirname(filename), name);
        const local = [`${base}.ts`, `${base}.tsx`].find(existsSync);
        assert.ok(local, `Missing local module ${name}`);
        return load(local);
      }
      return nodeRequire(name);
    }
    scripts.get(filename)(compiledModule, compiledModule.exports, dependency, { env }, fetchFixture);
    return compiledModule.exports;
  }
  return { calls, load: filename => load(path.join(frontend, filename)), route };
}

async function render(t, options) {
  const f = fixture(options);
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  t.after(async () => { await act(async () => root.unmount()); container.remove(); });
  const { PortalRoute } = f.load('components/portal-route.tsx');
  const area = f.route.startsWith('/admin') ? 'admin' : f.route === '/' ? 'root' : 'student';
  await act(async () => root.render(React.createElement(PortalRoute, { area })));
  return { ...f, container };
}

async function click(element) {
  assert.ok(element);
  assert.notEqual(element.disabled, true);
  await act(async () => element.click());
}

function button(container, text) {
  return [...container.querySelectorAll('button')].find(item => item.textContent.trim().includes(text));
}

async function select(element, value) {
  assert.ok(element);
  assert.notEqual(element.disabled, true);
  await act(async () => {
    element.value = value;
    assert.equal(element.value, value);
    element.dispatchEvent(new window.Event('change', { bubbles: true }));
  });
}

function checkReads(f, expected) {
  assert.deepEqual(f.calls.requests.map(request => request.parsed.pathname).sort(), [...expected].sort());
  for (const { url, method, init } of f.calls.requests) {
    assert.match(url, /^\/api\//);
    assert.equal(method, 'GET');
    assert.equal(init.body, undefined);
    assert.equal(init.credentials, 'omit');
    assert.equal(init.redirect, 'error');
    assert.equal(init.headers.get('Authorization'), `Bearer ${token}`);
  }
  assert.doesNotMatch(f.container.innerHTML, /SYNTHETIC_ACCESS_CANARY|observatory|risk-observation|raw-trace|\.local-legacy/i);
}

test('ADMIN overview uses read counts and a view-only scores shortcut', async t => {
  const f = await render(t, { route: '/admin' });
  assert.match(f.container.textContent, /Tra cứu hồ sơ/);
  assert.doesNotMatch(f.container.textContent, /Thêm sinh viên|Tạo lớp|Thêm môn học|Nhập và sửa điểm/);
  await click(button(f.container, 'Xem bảng điểm'));
  assert.deepEqual(f.calls.routes, ['/admin/scores']);
  checkReads(f, ['/api/admin/students', '/api/admin/student-classes', '/api/admin/subjects']);
});

test('ADMIN can search and open a student profile and navigate to scores without an edit form', async t => {
  const f = await render(t, { route: '/admin/students' });
  assert.match(f.container.querySelector('tbody').textContent, /SYNTH-STUDENT/);
  assert.equal(button(f.container, 'Thêm sinh viên'), undefined);
  await click(f.container.querySelector('form.admin-filters button[type="submit"]'));
  await click(f.container.querySelector('[title="Xem hồ sơ"]'));
  const modal = f.container.querySelector('[role="dialog"]');
  assert.match(modal.querySelector('dl').textContent, /SYNTH-STUDENT/);
  assert.equal(modal.querySelector('form, input, select, textarea'), null);
  await click(button(modal, 'Xem bảng điểm'));
  assert.deepEqual(f.calls.routes, ['/admin/scores']);
  checkReads(f, ['/api/admin/students', '/api/admin/students', '/api/admin/student-classes', studentUrl]);
});

for (const [route, list, label, add, remove] of [
  ['classes', 'student-classes', 'SYNTH-CLASS', 'Tạo lớp', 'Xóa lớp'],
  ['subjects', 'subjects', 'SYNTH-SUBJECT', 'Thêm môn học', 'Xóa môn học'],
]) {
  test(`ADMIN ${route} catalog can be filtered with no create or delete controls`, async t => {
    const f = await render(t, { route: `/admin/${route}` });
    assert.match(f.container.querySelector('tbody').textContent, new RegExp(label));
    assert.equal(button(f.container, add), undefined);
    assert.equal(f.container.querySelector(`[title="${remove}"], th[aria-label="Thao tác"]`), null);
    await click(button(f.container, 'Lọc dữ liệu'));
    checkReads(f, [`/api/admin/${list}`, `/api/admin/${list}`]);
  });
}

test('ADMIN score views use persisted grades, keep read filters, and cannot edit or save', async t => {
  const f = await render(t, { route: '/admin/scores' });
  assert.doesNotMatch(f.container.textContent, /nhập điểm/i);
  await select(f.container.querySelector('select[aria-label="Chọn sinh viên"]'), student.id);
  assert.match(f.container.querySelector('tbody').textContent, /Synthetic subject.*B\+/);
  assert.equal(f.container.querySelector('[title="Sửa điểm"], [title="Xóa điểm"]'), null);
  await click(f.container.querySelector('form.admin-filters button[type="submit"]'));
  await click(button(f.container, 'Theo môn học'));
  const filters = f.container.querySelector('.subject-score-filters');
  const selects = filters.querySelectorAll('select');
  assert.equal(selects.length, 2, 'The sheet endpoint filters by subject and class, not a simulated semester/year');
  await select(selects[0], subject.id);
  await select(selects[1], schoolClass.classCode);
  await click(button(filters, 'Tải danh sách'));
  const sheet = f.container.querySelector('.subject-score-table');
  assert.match(sheet.querySelector('.score-total').textContent, /^8[.,]4$/);
  assert.match(sheet.textContent, /B\+.*HK 2.*2025-2026/);
  assert.equal(sheet.querySelector('input, [contenteditable]'), null);
  assert.equal(button(f.container, 'Lưu bảng điểm'), undefined);
  assert.equal(f.calls.requests.find(r => r.parsed.pathname === sheetUrl).parsed.searchParams.get('classCode'), schoolClass.classCode);
  checkReads(f, ['/api/admin/students', '/api/admin/subjects', `${studentUrl}/scores`,
    `${studentUrl}/scores`, '/api/admin/student-classes', sheetUrl]);
});

test('ADMIN account security and the existing MFA reset dialog remain available', async t => {
  const f = await render(t, { route: '/admin/users' });
  assert.equal(new URL(f.container.querySelector('a[aria-label="Bảo mật tài khoản"]').href).origin, authOrigin);
  await click(f.container.querySelector('[title="Reset MFA"]'));
  assert.match(f.container.querySelector('[role="dialog"]').textContent, /Reset MFA/);
  checkReads(f, ['/api/admin/users']);
  // The POST is exercised against an in-memory fetch stub, without resetting any account.
  await f.load('lib/admin-api.ts').adminRequest(resetUrl, { method: 'POST' });
  assert.equal(f.calls.requests.at(-1).method, 'POST');
  assert.equal(f.calls.requests.at(-1).url, resetUrl);
});

test('STUDENT sees own profile, summary and grades with no administration or operator links', async t => {
  const f = await render(t, { route: '/student/scores', roles: ['STUDENT'] });
  assert.match(f.container.textContent, /SYNTH-STUDENT/);
  assert.match(f.container.querySelector('tbody').textContent, /Synthetic subject.*B\+/);
  assert.equal(f.container.querySelector('a[href^="/admin"], [title="Reset MFA"]'), null);
  checkReads(f, ['/api/users/me', '/api/students/me', '/api/students/me/scores/summary', '/api/students/me/scores']);
});

test('STUDENT on a direct ADMIN route is redirected before any API call', async t => {
  const f = await render(t, { route: '/admin/students', roles: ['STUDENT'] });
  assert.deepEqual(f.calls.routes, ['/student/scores']);
  assert.deepEqual(f.calls.requests, []);
});

test('Public Demo root still uses the Keycloak login adapter and same-origin PKCE check-sso', async t => {
  const f = await render(t, { authenticated: false });
  await click(button(f.container, 'Đăng nhập với Keycloak'));
  assert.deepEqual(f.calls.construct, [{ url: authOrigin, realm: 'synthetic-demo', clientId: 'zerotrust-spa' }]);
  assert.equal(f.calls.init[0].pkceMethod, 'S256');
  assert.equal(f.calls.init[0].onLoad, 'check-sso');
  assert.equal(f.calls.init[0].silentCheckSsoRedirectUri, `${origin}/silent-check-sso.html`);
  assert.deepEqual(f.calls.login, [{ redirectUri: `${origin}/`, locale: 'vi' }]);
  assert.deepEqual(f.calls.requests, []);
});

test('Loading, redacted API/network errors and empty retry states stay readable', async t => {
  let pending;
  let attempt = 0;
  const f = await render(t, { route: '/admin/subjects', respond() {
    attempt++;
    if (attempt === 1) return new Promise(resolve => { pending = resolve; });
    if (attempt === 2) return Promise.reject(new Error('OPERATOR-PRIVATE-NETWORK-CANARY'));
    return Response.json({ data: page([]) });
  } });
  assert.ok(f.container.querySelector('[aria-busy="true"]'));
  await act(async () => pending(Response.json({ message: 'OPERATOR-PRIVATE-PAYLOAD-CANARY' }, { status: 503 })));
  assert.match(f.container.querySelector('[role="alert"]').textContent, /503/);
  await click(button(f.container, 'Thử lại'));
  assert.match(f.container.querySelector('[role="alert"]').textContent, /Không thể hoàn tất/);
  await click(button(f.container, 'Thử lại'));
  assert.match(f.container.querySelector('tbody').textContent, /Chưa có môn học phù hợp/);
  assert.doesNotMatch(f.container.textContent, /OPERATOR-PRIVATE|tạo môn học mới/i);
  checkReads(f, Array(3).fill('/api/admin/subjects'));
});

test('Adapter rejects academic writes and unclassified, private or off-origin requests before refresh', async () => {
  const f = fixture();
  const { apiFetch } = f.load('lib/api.ts');
  const scoreUrl = `/api/admin/scores/${score.id}`;
  for (const [method, url, body] of [
    ['POST', '/api/admin/students'], ['PATCH', studentUrl],
    ['POST', '/api/admin/student-classes'], ['DELETE', `/api/admin/student-classes/${schoolClass.id}`],
    ['POST', '/api/admin/subjects'], ['DELETE', `/api/admin/subjects/${subject.id}`],
    ['POST', `${studentUrl}/scores`], ['PATCH', scoreUrl], ['DELETE', scoreUrl],
    ['POST', `/api/admin/subjects/${subject.id}/scores/batch`],
    ['POST', resetUrl, '{}'], ['GET', studentUrl, '{}'], ['GET', '/api/admin/scores/export'],
    ['GET', '/api/risk/observatory'], ['GET', '/.local-legacy/risk-observation/latest/index.json'],
    ['GET', 'https://auth.example.invalid/api/admin/users'], ['GET', '//private.example.invalid/api/users/me'],
  ]) {
    await assert.rejects(apiFetch(url, { method, body }), /không khả dụng/);
  }
  assert.deepEqual(f.calls.requests, []);
  assert.deepEqual(f.calls.refresh, []);
});

test('Standard mode still renders and submits the academic create-class form', async t => {
  const f = await render(t, { mode: 'standard', route: '/admin/classes', respond({ method }) {
    if (method === 'POST') return Response.json({ data: schoolClass }, { status: 201 });
  } });
  await click(button(f.container, 'Tạo lớp'));
  const form = f.container.querySelector('[role="dialog"] form');
  for (const key of ['classCode', 'className', 'courseYears']) form.elements.namedItem(key).value = schoolClass[key];
  const department = form.elements.namedItem('department');
  department.selectedIndex = 1;
  await act(async () => form.dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true })));
  const post = f.calls.requests.find(request => request.method === 'POST');
  assert.equal(post?.url, '/api/admin/student-classes');
  assert.equal(JSON.parse(post.init.body).classCode, schoolClass.classCode);
  assert.equal(post.init.redirect, undefined);
});
