import Keycloak from 'keycloak-js';

let keycloak: Keycloak | undefined;
let initialization: Promise<boolean> | undefined;

export function getKeycloak(): Keycloak {
  if (typeof window === 'undefined') {
    throw new Error('Keycloak can only be initialized in the browser');
  }

  keycloak ??= new Keycloak({
    url: process.env.NEXT_PUBLIC_KEYCLOAK_URL ?? 'http://localhost:8180',
    realm: process.env.NEXT_PUBLIC_KEYCLOAK_REALM ?? 'DoAn',
    clientId: process.env.NEXT_PUBLIC_KEYCLOAK_CLIENT_ID ?? 'zerotrust-spa',
  });
  return keycloak;
}

export function initializeKeycloak(): Promise<boolean> {
  initialization ??= getKeycloak().init({
    onLoad: 'check-sso',
    pkceMethod: 'S256',
    checkLoginIframe: false,
    silentCheckSsoRedirectUri: `${window.location.origin}/silent-check-sso.html`,
  });
  return initialization;
}

export function appRedirectUri(): string {
  return `${window.location.origin}/`;
}
