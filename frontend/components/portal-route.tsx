'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import {
  ArrowRight,
  CheckCircle2,
  KeyRound,
  LockKeyhole,
  LogOut,
  ServerOff,
  ShieldCheck,
} from 'lucide-react';
import { AdminPortal, ADMIN_VIEW_PATHS } from './admin-portal';
import type { AdminView } from './admin-portal';
import { StudentScoreDashboard } from './student-score-dashboard';
import { AuthenticationExpiredError } from '../lib/api';
import { appRedirectUri, getKeycloak, initializeKeycloak } from '../lib/keycloak';

type Identity = {
  username: string;
  roles: string[];
};

type AccessState = 'checking' | 'admin' | 'student' | 'unauthenticated' | 'forbidden' | 'offline';
type PortalArea = 'root' | 'admin' | 'student';

const ADMIN_PATH_VIEWS = Object.fromEntries(
  Object.entries(ADMIN_VIEW_PATHS).map(([view, path]) => [path, view]),
) as Record<string, AdminView>;

function currentIdentity(): Identity {
  const keycloak = getKeycloak();
  const claims = keycloak.tokenParsed as { preferred_username?: string } | undefined;
  return {
    username: claims?.preferred_username ?? keycloak.subject ?? 'Người dùng',
    roles: (keycloak.realmAccess?.roles ?? []).map((role) => role.toUpperCase()),
  };
}

function AuthLoading() {
  return (
    <main className="auth-loading" role="status" aria-live="polite">
      <span className="brand-mark"><ShieldCheck aria-hidden="true" size={22} /></span>
      <span className="auth-spinner" aria-hidden="true" />
      <p>Đang kiểm tra đăng nhập với Keycloak…</p>
    </main>
  );
}

function LoginScreen({ identityUnavailable = false, onLogin }: { identityUnavailable?: boolean; onLogin: () => void }) {
  return (
    <main className="login-screen">
      <section className="login-intro" aria-labelledby="login-brand-title">
        <div className="login-brand">
          <span className="brand-mark"><ShieldCheck aria-hidden="true" size={22} /></span>
          <div><strong>ZeroTrust</strong><span>Academic Portal</span></div>
        </div>
        <div className="login-intro-copy">
          <p className="login-kicker">Cổng học vụ bảo mật</p>
          <h1 id="login-brand-title">Dữ liệu học vụ của bạn, được bảo vệ tốt hơn.</h1>
          <p>Một lần đăng nhập qua Keycloak để quản trị dữ liệu hoặc theo dõi kết quả học tập theo đúng quyền được cấp.</p>
        </div>
        <div className="login-assurances" aria-label="Các lớp bảo vệ đăng nhập">
          <span><LockKeyhole aria-hidden="true" size={17} /> Authorization Code + PKCE S256</span>
          <span><ShieldCheck aria-hidden="true" size={17} /> Xác thực thích ứng theo rủi ro</span>
          <span><CheckCircle2 aria-hidden="true" size={17} /> Token chỉ giữ trong bộ nhớ</span>
        </div>
      </section>

      <section className="login-action" aria-labelledby="login-title">
        <div className="login-card">
          {identityUnavailable ? <>
            <span className="login-icon login-icon-warning"><ServerOff aria-hidden="true" size={25} /></span>
            <p className="login-kicker">Kết nối hệ thống</p>
            <h2 id="login-title">Chưa thể kết nối máy chủ</h2>
            <p className="login-description">Keycloak hoặc Portal API chưa phản hồi. Hãy kiểm tra các dịch vụ rồi thử lại.</p>
            <button className="login-button" onClick={() => window.location.reload()} type="button">Thử kết nối lại <ArrowRight aria-hidden="true" size={18} /></button>
          </> : <>
            <span className="login-icon"><KeyRound aria-hidden="true" size={25} /></span>
            <p className="login-kicker">Đăng nhập hệ thống</p>
            <h2 id="login-title">Chào mừng bạn trở lại</h2>
            <p className="login-description">Tiếp tục tới Keycloak để đăng nhập bằng tài khoản được nhà trường cấp.</p>
            <button className="login-button" onClick={onLogin} type="button">Đăng nhập với Keycloak <ArrowRight aria-hidden="true" size={18} /></button>
            <p className="login-footnote">Mật khẩu và mã MFA chỉ được nhập trên trang xác thực của Keycloak.</p>
          </>}
        </div>
      </section>
    </main>
  );
}

function ForbiddenScreen({ onLogout }: { onLogout: () => void }) {
  return (
    <main className="access-page"><div className="access-dialog">
      <span className="access-mark"><ShieldCheck aria-hidden="true" size={23} /></span>
      <p className="eyebrow">ZeroTrust Academic Portal</p><h1>Chưa có quyền truy cập</h1>
      <p>Access token hiện tại không có role ADMIN hoặc STUDENT. Hãy sử dụng tài khoản phù hợp.</p>
      <button className="login-button" onClick={onLogout} type="button">Đăng xuất <LogOut aria-hidden="true" size={18} /></button>
    </div></main>
  );
}

export function PortalRoute({ area }: { area: PortalArea }) {
  const pathname = usePathname();
  const router = useRouter();
  const [accessState, setAccessState] = useState<AccessState>('checking');
  const [identity, setIdentity] = useState<Identity | null>(null);
  const adminView = useMemo(() => ADMIN_PATH_VIEWS[pathname], [pathname]);

  useEffect(() => {
    let active = true;
    async function bootstrap() {
      try {
        const authenticated = await initializeKeycloak();
        if (!active) return;
        const keycloak = getKeycloak();
        keycloak.onAuthLogout = () => active && setAccessState('unauthenticated');
        keycloak.onAuthRefreshError = () => active && setAccessState('unauthenticated');
        if (!authenticated) { setAccessState('unauthenticated'); return; }

        const loggedInIdentity = currentIdentity();
        setIdentity(loggedInIdentity);
        if (loggedInIdentity.roles.includes('STUDENT') && !loggedInIdentity.roles.includes('ADMIN')) {
          setAccessState('student'); return;
        }
        setAccessState(loggedInIdentity.roles.includes('ADMIN') ? 'admin' : 'forbidden');
      } catch (error) {
        if (!active) return;
        setAccessState(error instanceof AuthenticationExpiredError ? 'unauthenticated' : 'offline');
      }
    }
    void bootstrap();
    return () => {
      active = false;
      if (typeof window !== 'undefined') {
        const keycloak = getKeycloak();
        keycloak.onAuthLogout = undefined;
        keycloak.onAuthRefreshError = undefined;
      }
    };
  }, []);

  useEffect(() => {
    if (accessState === 'unauthenticated' && area !== 'root') {
      window.location.replace('/');
      return;
    }
    if (accessState === 'admin' && area !== 'admin') {
      router.replace('/admin');
      return;
    }
    if (accessState === 'student' && area !== 'student') {
      router.replace('/student/scores');
      return;
    }
    if (accessState === 'admin' && area === 'admin' && !adminView) {
      router.replace('/admin');
    }
  }, [accessState, adminView, area, router]);

  const authenticationExpired = useCallback(() => {
    getKeycloak().clearToken();
    window.location.replace('/');
  }, []);
  const login = useCallback(() => { void getKeycloak().login({ redirectUri: appRedirectUri() }); }, []);
  const logout = useCallback(() => {
    setAccessState('checking');
    void getKeycloak().logout({ redirectUri: appRedirectUri() }).catch(() => {
      getKeycloak().clearToken();
      window.location.replace('/');
    });
  }, []);

  if (accessState === 'checking') return <AuthLoading />;
  if (accessState === 'unauthenticated') return area === 'root' ? <LoginScreen onLogin={login} /> : <AuthLoading />;
  if (accessState === 'offline') return <LoginScreen identityUnavailable onLogin={login} />;
  if (accessState === 'forbidden') return <ForbiddenScreen onLogout={logout} />;
  if (accessState === 'student' && area === 'student' && identity) {
    return <StudentScoreDashboard username={identity.username} onAuthenticationExpired={authenticationExpired} onLogout={logout} />;
  }
  if (accessState === 'admin' && area === 'admin' && adminView && identity) {
    return <AdminPortal username={identity.username} view={adminView} onAuthenticationExpired={authenticationExpired} onLogout={logout} />;
  }
  return <AuthLoading />;
}
