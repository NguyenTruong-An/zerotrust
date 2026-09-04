'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  ArrowRight,
  BookOpen,
  CalendarDays,
  CheckCircle2,
  ClipboardCheck,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Menu,
  Plus,
  School,
  ServerOff,
  ShieldCheck,
  UsersRound,
} from 'lucide-react';
import { apiFetch, AuthenticationExpiredError } from '../lib/api';
import { appRedirectUri, getKeycloak, initializeKeycloak } from '../lib/keycloak';
import { StudentScoreDashboard } from '../components/student-score-dashboard';

type Identity = {
  username: string;
  roles: string[];
};

type PageResponse<T> = {
  content: T[];
  totalElements: number;
};

type ApiResponse<T> = {
  data: T;
  message: string;
  success: boolean;
};

type AccessState = 'checking' | 'admin' | 'student' | 'unauthenticated' | 'forbidden' | 'offline';

const navItems = [
  { icon: LayoutDashboard, label: 'Tổng quan', active: true },
  { icon: UsersRound, label: 'Sinh viên' },
  { icon: School, label: 'Lớp hành chính' },
  { icon: BookOpen, label: 'Môn học' },
  { icon: ClipboardCheck, label: 'Điểm số' },
];

const quickActions = [
  {
    icon: Plus,
    title: 'Thêm sinh viên',
    description: 'Tạo tài khoản Keycloak và hồ sơ sinh viên mới.',
    accent: 'coral',
  },
  {
    icon: ClipboardCheck,
    title: 'Nhập điểm',
    description: 'Cập nhật điểm theo sinh viên, môn học và học kỳ.',
    accent: 'teal',
  },
  {
    icon: School,
    title: 'Tạo lớp',
    description: 'Khai báo lớp hành chính cho năm học mới.',
    accent: 'blue',
  },
];

function formatNumber(value: number | null) {
  return value === null ? '—' : new Intl.NumberFormat('vi-VN').format(value);
}

async function getTotal(path: string): Promise<number> {
  const response = await apiFetch(path);
  if (!response.ok) {
    throw new Error(`Request failed with ${response.status}`);
  }
  const payload = (await response.json()) as ApiResponse<PageResponse<unknown>>;
  return payload.data.totalElements;
}

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

function LoginScreen({
  identityUnavailable = false,
  onLogin,
}: {
  identityUnavailable?: boolean;
  onLogin: () => void;
}) {
  return (
    <main className="login-screen">
      <section className="login-intro" aria-labelledby="login-brand-title">
        <div className="login-brand">
          <span className="brand-mark"><ShieldCheck aria-hidden="true" size={22} /></span>
          <div>
            <strong>ZeroTrust</strong>
            <span>Academic Portal</span>
          </div>
        </div>

        <div className="login-intro-copy">
          <p className="login-kicker">Cổng học vụ bảo mật</p>
          <h1 id="login-brand-title">Dữ liệu học vụ của bạn, được bảo vệ tốt hơn.</h1>
          <p>
            Một lần đăng nhập qua Keycloak để quản trị dữ liệu hoặc theo dõi
            kết quả học tập theo đúng quyền được cấp.
          </p>
        </div>

        <div className="login-assurances" aria-label="Các lớp bảo vệ đăng nhập">
          <span><LockKeyhole aria-hidden="true" size={17} /> Authorization Code + PKCE S256</span>
          <span><ShieldCheck aria-hidden="true" size={17} /> MFA qua Keycloak</span>
          <span><CheckCircle2 aria-hidden="true" size={17} /> Token chỉ giữ trong bộ nhớ</span>
        </div>
      </section>

      <section className="login-action" aria-labelledby="login-title">
        <div className="login-card">
          {identityUnavailable ? (
            <>
              <span className="login-icon login-icon-warning"><ServerOff aria-hidden="true" size={25} /></span>
              <p className="login-kicker">Kết nối hệ thống</p>
              <h2 id="login-title">Chưa thể kết nối máy chủ</h2>
              <p className="login-description">
                Keycloak hoặc Portal API chưa phản hồi. Hãy kiểm tra các dịch vụ rồi thử lại.
              </p>
              <button className="login-button" onClick={() => window.location.reload()} type="button">
                Thử kết nối lại <ArrowRight aria-hidden="true" size={18} />
              </button>
            </>
          ) : (
            <>
              <span className="login-icon"><KeyRound aria-hidden="true" size={25} /></span>
              <p className="login-kicker">Đăng nhập hệ thống</p>
              <h2 id="login-title">Chào mừng bạn trở lại</h2>
              <p className="login-description">
                Tiếp tục tới Keycloak để đăng nhập bằng tài khoản được nhà trường cấp.
              </p>
              <button className="login-button" onClick={onLogin} type="button">
                Đăng nhập với Keycloak <ArrowRight aria-hidden="true" size={18} />
              </button>
              <p className="login-footnote">
                Mật khẩu và mã MFA chỉ được nhập trên trang xác thực của Keycloak.
              </p>
            </>
          )}
        </div>
      </section>
    </main>
  );
}

function ForbiddenScreen({ onLogout }: { onLogout: () => void }) {
  return (
    <main className="access-page">
      <div className="access-dialog">
        <span className="access-mark"><ShieldCheck aria-hidden="true" size={23} /></span>
        <p className="eyebrow">ZeroTrust Academic Portal</p>
        <h1>Chưa có quyền truy cập</h1>
        <p>Access token hiện tại không có role ADMIN hoặc STUDENT. Hãy sử dụng tài khoản phù hợp.</p>
        <button className="login-button" onClick={onLogout} type="button">
          Đăng xuất <LogOut aria-hidden="true" size={18} />
        </button>
      </div>
    </main>
  );
}

export default function AdminDashboard() {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [accessState, setAccessState] = useState<AccessState>('checking');
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [stats, setStats] = useState({
    students: null,
    classes: null,
    subjects: null,
  } as { students: number | null; classes: number | null; subjects: number | null });

  useEffect(() => {
    let active = true;

    async function bootstrap() {
      try {
        const authenticated = await initializeKeycloak();
        if (!active) return;

        const keycloak = getKeycloak();
        keycloak.onAuthLogout = () => active && setAccessState('unauthenticated');
        keycloak.onAuthRefreshError = () => active && setAccessState('unauthenticated');

        if (!authenticated) {
          setAccessState('unauthenticated');
          return;
        }

        const loggedInIdentity = currentIdentity();
        setIdentity(loggedInIdentity);
        if (loggedInIdentity.roles.includes('STUDENT') && !loggedInIdentity.roles.includes('ADMIN')) {
          setAccessState('student');
          return;
        }

        if (!loggedInIdentity.roles.includes('ADMIN')) {
          setAccessState('forbidden');
          return;
        }

        const [students, classes, subjects] = await Promise.all([
          getTotal('/api/admin/students?page=0&size=1'),
          getTotal('/api/admin/student-classes?page=0&size=1'),
          getTotal('/api/admin/subjects?page=0&size=1'),
        ]);
        if (!active) return;
        setStats({ students, classes, subjects });
        setAccessState('admin');
      } catch (error) {
        if (!active) return;
        setAccessState(
          error instanceof AuthenticationExpiredError ? 'unauthenticated' : 'offline',
        );
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

  const today = useMemo(
    () =>
      new Intl.DateTimeFormat('vi-VN', {
        weekday: 'long',
        day: '2-digit',
        month: 'long',
        year: 'numeric',
      }).format(new Date()),
    [],
  );

  const login = () => {
    void getKeycloak().login({ redirectUri: appRedirectUri() });
  };

  const logout = () => {
    setAccessState('checking');
    void getKeycloak()
      .logout({ redirectUri: appRedirectUri() })
      .catch(() => {
        getKeycloak().clearToken();
        setIdentity(null);
        setAccessState('unauthenticated');
      });
  };

  if (accessState === 'checking') return <AuthLoading />;
  if (accessState === 'unauthenticated') return <LoginScreen onLogin={login} />;
  if (accessState === 'offline') return <LoginScreen identityUnavailable onLogin={login} />;
  if (accessState === 'forbidden') return <ForbiddenScreen onLogout={logout} />;
  if (accessState === 'student' && identity) {
    return (
      <StudentScoreDashboard
        username={identity.username}
        onAuthenticationExpired={() => setAccessState('unauthenticated')}
        onLogout={logout}
      />
    );
  }

  return (
    <main className="admin-shell">
      <aside className={`sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <span className="brand-mark"><ShieldCheck aria-hidden="true" size={21} /></span>
          <div>
            <strong>ZeroTrust</strong>
            <span>Academic Portal</span>
          </div>
        </div>

        <div className="nav-label">Quản trị hệ thống</div>
        <nav aria-label="Điều hướng quản trị">
          {navItems.map((item) => (
            <button
              className={`nav-item ${item.active ? 'nav-item-active' : ''}`}
              key={item.label}
              onClick={() => setMobileNavOpen(false)}
              type="button"
            >
              <span className="nav-code"><item.icon aria-hidden="true" size={18} strokeWidth={1.9} /></span>
              <span>{item.label}</span>
            </button>
          ))}
        </nav>

        <p className="sidebar-version">ZeroTrust Portal · SPA/PKCE</p>
      </aside>

      {mobileNavOpen && (
        <button
          aria-label="Đóng menu"
          className="sidebar-backdrop"
          onClick={() => setMobileNavOpen(false)}
          type="button"
        />
      )}

      <section className="workspace">
        <header className="topbar">
          <button
            aria-label="Mở menu"
            className="menu-button"
            onClick={() => setMobileNavOpen(true)}
            type="button"
          >
            <Menu aria-hidden="true" size={20} />
          </button>
          <div className="topbar-title">
            <span>Không gian quản trị</span>
            <strong>Bảng điều khiển</strong>
          </div>
          <div className="topbar-actions">
            <div className="profile">
              <span className="avatar">{identity?.username.slice(0, 2).toUpperCase() || 'AD'}</span>
              <div>
                <strong>{identity?.username || 'Quản trị viên'}</strong>
                <span>ADMIN</span>
              </div>
            </div>
            <button aria-label="Đăng xuất" className="logout-button" onClick={logout} type="button">
              <LogOut aria-hidden="true" size={18} />
            </button>
          </div>
        </header>

        <div className="content">
          <section className="hero" aria-labelledby="dashboard-heading">
            <div>
              <p className="eyebrow">{today}</p>
              <h1 id="dashboard-heading">
                Xin chào, <span>{identity?.username || 'Quản trị viên'}.</span>
              </h1>
              <p className="hero-copy">
                Theo dõi dữ liệu học vụ và xử lý các công việc quan trọng từ một nơi duy nhất.
              </p>
            </div>
            <div className="term-card">
              <div className="term-topline">
                <span><CalendarDays aria-hidden="true" size={16} /> Học kỳ hiện tại</span>
                <b>HK 1</b>
              </div>
              <strong>2026 — 2027</strong>
              <div className="term-progress"><span /></div>
              <p>Hệ thống đang sẵn sàng tiếp nhận dữ liệu học vụ.</p>
            </div>
          </section>

          <section className="stats-grid" aria-label="Thống kê tổng quan">
            <article className="stat-card stat-primary">
              <div className="stat-index">01</div>
              <p>Sinh viên</p>
              <strong>{formatNumber(stats.students)}</strong>
              <span>Tổng hồ sơ trong hệ thống</span>
            </article>
            <article className="stat-card">
              <div className="stat-index">02</div>
              <p>Lớp hành chính</p>
              <strong>{formatNumber(stats.classes)}</strong>
              <span>Đang được quản lý</span>
            </article>
            <article className="stat-card">
              <div className="stat-index">03</div>
              <p>Môn học</p>
              <strong>{formatNumber(stats.subjects)}</strong>
              <span>Trong danh mục đào tạo</span>
            </article>
            <article className="stat-card stat-dark">
              <div className="stat-index">V3</div>
              <p>Bảo mật truy cập</p>
              <strong>Đã xác thực</strong>
              <span>Bearer JWT · PKCE S256</span>
            </article>
          </section>

          <section className="dashboard-grid">
            <div className="quick-section">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">Thao tác nhanh</p>
                  <h2>Bắt đầu công việc</h2>
                </div>
                <span>3 tác vụ chính</span>
              </div>
              <div className="quick-list">
                {quickActions.map((action) => (
                  <div className="quick-action" key={action.title}>
                    <span className={`quick-code ${action.accent}`}>
                      <action.icon aria-hidden="true" size={19} strokeWidth={1.9} />
                    </span>
                    <span className="quick-copy">
                      <strong>{action.title}</strong>
                      <small>{action.description}</small>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </section>
        </div>
      </section>
    </main>
  );
}
