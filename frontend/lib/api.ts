import { getKeycloak } from './keycloak';

const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8080'
).replace(/\/$/, '');

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
    headers,
    credentials: 'omit',
  });
}

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  await refreshToken();
  let response = await request(path, init);

  if (response.status === 401) {
    await refreshToken(true);
    response = await request(path, init);
  }

  return response;
}
