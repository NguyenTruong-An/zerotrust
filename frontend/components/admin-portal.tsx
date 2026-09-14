'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import type { LucideIcon } from 'lucide-react';
import {
  BookOpen,
  CalendarDays,
  CheckCircle2,
  ClipboardCheck,
  LayoutDashboard,
  LogOut,
  Menu,
  Plus,
  School,
  ShieldCheck,
  UserCog,
  UsersRound,
  X,
} from 'lucide-react';
import { AuthenticationExpiredError } from '../lib/api';
import { adminRequest, PageResponse, Student } from '../lib/admin-api';
import { ClassesPanel, SubjectsPanel, UsersPanel } from './admin-catalogs';
import { ScoresPanel } from './admin-scores';
import { StudentsPanel } from './admin-students';

export type AdminView = 'overview' | 'students' | 'classes' | 'subjects' | 'scores' | 'users';

export const ADMIN_VIEW_PATHS: Record<AdminView, string> = {
  overview: '/admin',
  students: '/admin/students',
  classes: '/admin/classes',
  subjects: '/admin/subjects',
  scores: '/admin/scores',
  users: '/admin/users',
};

type AdminPortalProps = {
  username: string;
  view: AdminView;
  onAuthenticationExpired: () => void;
  onLogout: () => void;
};

type NavItem = {
  id: AdminView;
  label: string;
  icon: LucideIcon;
};

const NAV_ITEMS: NavItem[] = [
  { id: 'overview', icon: LayoutDashboard, label: 'Tổng quan' },
  { id: 'students', icon: UsersRound, label: 'Sinh viên' },
  { id: 'classes', icon: School, label: 'Lớp' },
  { id: 'subjects', icon: BookOpen, label: 'Môn học' },
  { id: 'scores', icon: ClipboardCheck, label: 'Điểm số' },
  { id: 'users', icon: UserCog, label: 'Tài khoản' },
];

const VIEW_TITLES: Record<AdminView, string> = {
  overview: 'Bảng điều khiển',
  students: 'Quản lý sinh viên',
  classes: 'Lớp',
  subjects: 'Danh mục môn học',
  scores: 'Quản lý điểm',
  users: 'Tài khoản người dùng',
};

function formatNumber(value: number | null): string {
  return value === null ? '—' : new Intl.NumberFormat('vi-VN').format(value);
}

export function AdminPortal({ username, view, onAuthenticationExpired, onLogout }: AdminPortalProps) {
  const router = useRouter();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [statsVersion, setStatsVersion] = useState(0);
  const [scoreStudent, setScoreStudent] = useState<Student | null>(null);

  const navigate = useCallback((nextView: AdminView) => {
    router.push(ADMIN_VIEW_PATHS[nextView]);
    setMobileNavOpen(false);
  }, [router]);

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, [view]);

  const openStudentScores = useCallback((student: Student) => {
    setScoreStudent(student);
    navigate('scores');
  }, [navigate]);

  const markChanged = useCallback(() => setStatsVersion((value) => value + 1), []);
  const notify = useCallback((message: string) => setNotice(message), []);

  return (
    <main className="admin-shell">
      <aside className={`sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <span className="brand-mark"><ShieldCheck aria-hidden="true" size={21} /></span>
          <div><strong>ZeroTrust</strong><span>Academic Portal</span></div>
        </div>
        <div className="nav-label">Quản trị hệ thống</div>
        <nav aria-label="Điều hướng quản trị">
          {NAV_ITEMS.map((item) => (
            <Link
              aria-current={view === item.id ? 'page' : undefined}
              className={`nav-item ${view === item.id ? 'nav-item-active' : ''}`}
              href={ADMIN_VIEW_PATHS[item.id]}
              key={item.id}
              onClick={() => setMobileNavOpen(false)}
            >
              <span className="nav-code"><item.icon aria-hidden="true" size={18} strokeWidth={1.9} /></span>
              <span>{item.label}</span>
            </Link>
          ))}
        </nav>
        <p className="sidebar-version">ZeroTrust Portal · Admin</p>
      </aside>

      {mobileNavOpen && <button aria-label="Đóng menu" className="sidebar-backdrop" onClick={() => setMobileNavOpen(false)} type="button" />}

      <section className="workspace">
        <header className="topbar">
          <button aria-label="Mở menu" className="menu-button" onClick={() => setMobileNavOpen(true)} type="button"><Menu aria-hidden="true" size={20} /></button>
          <div className="topbar-title"><span>Không gian quản trị</span><strong>{VIEW_TITLES[view]}</strong></div>
          <div className="topbar-actions">
            <div className="profile"><span className="avatar">{username.slice(0, 2).toUpperCase() || 'AD'}</span><div><strong>{username}</strong><span>ADMIN</span></div></div>
            <button aria-label="Đăng xuất" className="logout-button" onClick={onLogout} type="button"><LogOut aria-hidden="true" size={18} /></button>
          </div>
        </header>

        {notice && <div className="admin-toast" role="status"><CheckCircle2 aria-hidden="true" size={18} /><span>{notice}</span><button aria-label="Đóng thông báo" onClick={() => setNotice(null)} type="button"><X aria-hidden="true" size={15} /></button></div>}

        <div className="content admin-content">
          {view === 'overview' && <OverviewPanel key={statsVersion} onAuthenticationExpired={onAuthenticationExpired} onNavigate={navigate} username={username} />}
          {view === 'students' && <StudentsPanel onAuthenticationExpired={onAuthenticationExpired} onChanged={markChanged} onNotify={notify} onOpenScores={openStudentScores} />}
          {view === 'classes' && <ClassesPanel onAuthenticationExpired={onAuthenticationExpired} onChanged={markChanged} onNotify={notify} />}
          {view === 'subjects' && <SubjectsPanel onAuthenticationExpired={onAuthenticationExpired} onChanged={markChanged} onNotify={notify} />}
          {view === 'scores' && <ScoresPanel initialStudent={scoreStudent} onAuthenticationExpired={onAuthenticationExpired} onNotify={notify} />}
          {view === 'users' && <UsersPanel onAuthenticationExpired={onAuthenticationExpired} />}
        </div>
      </section>
    </main>
  );
}

function OverviewPanel({
  username,
  onAuthenticationExpired,
  onNavigate,
}: {
  username: string;
  onAuthenticationExpired: () => void;
  onNavigate: (view: AdminView) => void;
}) {
  const [stats, setStats] = useState({ students: null, classes: null, subjects: null } as Record<'students' | 'classes' | 'subjects', number | null>);
  const [loadingError, setLoadingError] = useState(false);

  useEffect(() => {
    let active = true;
    Promise.all([
      adminRequest<PageResponse<unknown>>('/api/admin/students?page=0&size=1'),
      adminRequest<PageResponse<unknown>>('/api/admin/student-classes?page=0&size=1'),
      adminRequest<PageResponse<unknown>>('/api/admin/subjects?page=0&size=1'),
    ])
      .then(([students, classes, subjects]) => {
        if (active) setStats({ students: students.totalElements, classes: classes.totalElements, subjects: subjects.totalElements });
      })
      .catch((caught) => {
        if (!active) return;
        if (caught instanceof AuthenticationExpiredError) onAuthenticationExpired();
        else setLoadingError(true);
      });
    return () => { active = false; };
  }, [onAuthenticationExpired]);

  const today = useMemo(() => new Intl.DateTimeFormat('vi-VN', { weekday: 'long', day: '2-digit', month: 'long', year: 'numeric' }).format(new Date()), []);

  return (
    <>
      <section className="hero" aria-labelledby="dashboard-heading">
        <div><p className="eyebrow">{today}</p><h1 id="dashboard-heading">Xin chào, <span>{username}.</span></h1><p className="hero-copy">Theo dõi dữ liệu học vụ và xử lý các công việc quan trọng từ một nơi duy nhất.</p>{loadingError && <p className="overview-warning">Chưa thể tải số liệu tổng quan. Các chức năng quản trị vẫn có thể sử dụng.</p>}</div>
        <div className="term-card"><div className="term-topline"><span><CalendarDays aria-hidden="true" size={16} /> Học kỳ hiện tại</span><b>HK 1</b></div><strong>2026 — 2027</strong><div className="term-progress"><span /></div><p>Hệ thống sẵn sàng tiếp nhận dữ liệu học vụ.</p></div>
      </section>

      <section className="stats-grid" aria-label="Thống kê tổng quan">
        <button className="stat-card stat-primary" onClick={() => onNavigate('students')} type="button"><div className="stat-index">01</div><p>Sinh viên</p><strong>{formatNumber(stats.students)}</strong><span>Tổng hồ sơ trong hệ thống</span></button>
        <button className="stat-card" onClick={() => onNavigate('classes')} type="button"><div className="stat-index">02</div><p>Lớp</p><strong>{formatNumber(stats.classes)}</strong><span>Đang được quản lý</span></button>
        <button className="stat-card" onClick={() => onNavigate('subjects')} type="button"><div className="stat-index">03</div><p>Môn học</p><strong>{formatNumber(stats.subjects)}</strong><span>Trong danh mục đào tạo</span></button>
      </section>

      <section className="dashboard-grid">
        <div className="quick-section">
          <div className="section-heading"><div><p className="eyebrow">Thao tác nhanh</p><h2>Bắt đầu công việc</h2></div></div>
          <div className="quick-list">
            <button className="quick-action" onClick={() => onNavigate('students')} type="button"><span className="quick-code coral"><Plus aria-hidden="true" size={19} /></span><span className="quick-copy"><strong>Thêm sinh viên</strong><small>Tạo tài khoản Keycloak và hồ sơ học vụ.</small></span></button>
            <button className="quick-action" onClick={() => onNavigate('scores')} type="button"><span className="quick-code teal"><ClipboardCheck aria-hidden="true" size={19} /></span><span className="quick-copy"><strong>Nhập và sửa điểm</strong><small>Chọn sinh viên, môn học và học kỳ.</small></span></button>
            <button className="quick-action" onClick={() => onNavigate('classes')} type="button"><span className="quick-code blue"><School aria-hidden="true" size={19} /></span><span className="quick-copy"><strong>Tạo lớp</strong><small>Khai báo lớp theo khóa học.</small></span></button>
            <button className="quick-action" onClick={() => onNavigate('subjects')} type="button"><span className="quick-code teal"><BookOpen aria-hidden="true" size={19} /></span><span className="quick-copy"><strong>Thêm môn học</strong><small>Cập nhật danh mục học phần và tín chỉ.</small></span></button>
          </div>
        </div>
      </section>
    </>
  );
}
