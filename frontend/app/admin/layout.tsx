import type { ReactNode } from 'react';
import { PortalRoute } from '../../components/portal-route';

export default function AdminLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <>
      <PortalRoute area="admin" />
      {children}
    </>
  );
}
