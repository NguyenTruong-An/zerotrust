import type { NextConfig } from 'next';

function publicOrigin(value: string | undefined, name: string): URL {
  try {
    const url = new URL(value ?? '');
    const dnsName = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/;
    if (url.protocol === 'https:' && value === url.origin && dnsName.test(url.hostname)
        && !url.hostname.split('.').some((label) => label === 'localhost' || /^lab(?:-|$)/.test(label))
        && !/\.(?:local|localhost|internal|lan)$/.test(url.hostname)) return url;
  } catch {
    // Report the variable name without echoing its value.
  }
  throw new Error(`Public Demo requires an explicit HTTPS origin in ${name}.`);
}

const mode = process.env.NEXT_PUBLIC_PORTAL_MODE ?? 'standard';
if (mode !== 'standard' && mode !== 'public-demo') {
  throw new Error('NEXT_PUBLIC_PORTAL_MODE must be standard or public-demo.');
}
if (mode === 'public-demo') {
  const portal = publicOrigin(process.env.NEXT_PUBLIC_SITE_URL, 'NEXT_PUBLIC_SITE_URL');
  const auth = publicOrigin(process.env.NEXT_PUBLIC_KEYCLOAK_URL, 'NEXT_PUBLIC_KEYCLOAK_URL');
  if (portal.hostname === auth.hostname) throw new Error('Public Demo requires distinct Portal and Keycloak hosts.');
  if (process.env.NEXT_PUBLIC_API_BASE_URL !== '') throw new Error('Public Demo requires a same-origin API.');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(process.env.NEXT_PUBLIC_KEYCLOAK_REALM ?? '')
      || process.env.NEXT_PUBLIC_KEYCLOAK_REALM?.toLowerCase() === 'master'
      || process.env.NEXT_PUBLIC_KEYCLOAK_CLIENT_ID !== 'zerotrust-spa') {
    throw new Error('Public Demo requires an explicit application realm and the zerotrust-spa public client.');
  }
}

const nextConfig: NextConfig = { output: 'standalone' };

export default nextConfig;
