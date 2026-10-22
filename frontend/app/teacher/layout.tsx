import type { ReactNode } from 'react';
import { PortalRoute } from '../../components/portal-route';
export default function TeacherLayout({ children }: Readonly<{ children: ReactNode }>) {
  return <><PortalRoute area="teacher" />{children}</>;
}
