import { getKeycloak } from './keycloak';

export const publicDemo = process.env.NEXT_PUBLIC_PORTAL_MODE === 'public-demo';

const API_BASE_URL = publicDemo ? '' : (
  process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8080'
).replace(/\/$/, '');

const id = '[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}';
const demoReadPath = new RegExp(`^(?:/api/users/me|/api/students/me(?:/scores(?:/summary)?)?|/api/admin/(?:students(?:/${id}(?:/scores)?)?|student-classes|subjects(?:/${id}/score-sheet)?|users))$`, 'i');
const resetPath = new RegExp(`^/api/admin/users/${id}/mfa/reset(?:/challenge)?$`, 'i');

let refreshInFlight: Promise<boolean> | undefined;

export class AuthenticationExpiredError extends Error {
  constructor() {
    super('The Keycloak session is no longer valid');
    this.name = 'AuthenticationExpiredError';
  }
}

async function refreshToken(force = false): Promise<void> {
  const keycloak = getKeycloak();
  if (!keycloak.authenticated) {
    throw new AuthenticationExpiredError();
  }

  refreshInFlight ??= keycloak
    .updateToken(force ? -1 : 30)
    .finally(() => {
      refreshInFlight = undefined;
    });

  try {
    await refreshInFlight;
  } catch {
    keycloak.clearToken();
    throw new AuthenticationExpiredError();
  }
}

async function request(path: string, init: RequestInit): Promise<Response> {
  const keycloak = getKeycloak();
  if (!keycloak.token) {
    throw new AuthenticationExpiredError();
  }

  const headers = new Headers(init.headers);
  headers.set('Authorization', `Bearer ${keycloak.token}`);
  return fetch(`${API_BASE_URL}${path}`, {
    ...init,
    ...(publicDemo ? { redirect: 'error' as const } : {}),
    headers,
    credentials: 'omit',
  });
}

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  if (publicDemo) {
    const pathname = path.split('?', 1)[0];
    const method = (init.method ?? 'GET').toUpperCase();
    const isRead = method === 'GET' && demoReadPath.test(pathname) && init.body == null;
    // D-10 keeps the existing ADMIN security-state action available.
    const isReset = method === 'POST' && resetPath.test(pathname) && init.body == null;
    if (!isRead && !isReset) throw new Error('Thao tác này không khả dụng trong Public Demo.');
  }
  await refreshToken();
  let response = await request(path, init);

  if (response.status === 401) {
    await refreshToken(true);
    response = await request(path, init);
  }

  return response;
}
