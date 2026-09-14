'use client';

import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import {
  BookOpenCheck,
  CalendarDays,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  CircleUserRound,
  GraduationCap,
  LogOut,
  Mail,
  MapPin,
  Menu,
  Phone,
  RefreshCw,
  Search,
  School,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react';
import { AuthenticationExpiredError } from '../lib/api';
import {
  emptyPage,
  PageResponse,
  portalRequest,
  queryPath,
  Score,
  Student,
  UserAccount,
} from '../lib/admin-api';
import { academicYearOptions } from '../lib/academic-years';
import { formatScore, scoreGradeTone } from '../lib/score-calculation';

type ScoreFilters = {
  keyword: string;
  academicYear: string;
  semester: string;
  sort: string;
};

type StudentScoreSummary = {
  totalSubjects: number;
  completedSubjects: number;
  passedSubjects: number;
  failedSubjects: number;
  averageScore: number | null;
  highestScore: number | null;
  latestSemester: number | null;
  latestAcademicYear: string | null;
};

type StudentScoreDashboardProps = {
  username: string;
  onLogout: () => void;
  onAuthenticationExpired: () => void;
};

const INITIAL_FILTERS: ScoreFilters = {
  keyword: '',
  academicYear: '',
  semester: '',
  sort: 'academicYear,desc',
};
const ACADEMIC_YEARS = academicYearOptions();

function formatDate(value: string | null | undefined): string {
  if (!value) return 'Chưa cập nhật';
  const [year, month, day] = value.split('-').map(Number);
  if (!year || !month || !day) return value;
  return new Intl.DateTimeFormat('vi-VN').format(new Date(year, month - 1, day));
}

function genderLabel(value: Student['gender'] | undefined): string {
  if (value === 'MALE') return 'Nam';
  if (value === 'FEMALE') return 'Nữ';
  if (value === 'OTHER') return 'Khác';
  return 'Chưa cập nhật';
}

export function StudentScoreDashboard({
  username,
  onLogout,
  onAuthenticationExpired,
}: StudentScoreDashboardProps) {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [account, setAccount] = useState<UserAccount | null>(null);
  const [student, setStudent] = useState<Student | null>(null);
  const [summary, setSummary] = useState<StudentScoreSummary | null>(null);
  const [identityLoading, setIdentityLoading] = useState(true);
  const [identityError, setIdentityError] = useState<string | null>(null);
  const [identityReloadKey, setIdentityReloadKey] = useState(0);
  const [draftFilters, setDraftFilters] = useState<ScoreFilters>(INITIAL_FILTERS);
  const [filters, setFilters] = useState<ScoreFilters>(INITIAL_FILTERS);
  const [page, setPage] = useState(0);
  const [scores, setScores] = useState<PageResponse<Score>>(emptyPage(10));
  const [scoresLoading, setScoresLoading] = useState(true);
  const [scoresError, setScoresError] = useState<string | null>(null);
  const [scoresReloadKey, setScoresReloadKey] = useState(0);

  const handleError = useCallback((caught: unknown, fallback: string): string | null => {
    if (caught instanceof AuthenticationExpiredError) {
      onAuthenticationExpired();
      return null;
    }
    return caught instanceof Error ? caught.message : fallback;
  }, [onAuthenticationExpired]);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    Promise.all([
      portalRequest<UserAccount>('/api/users/me', { signal: controller.signal }),
      portalRequest<Student>('/api/students/me', { signal: controller.signal }),
      portalRequest<StudentScoreSummary>('/api/students/me/scores/summary', {
        signal: controller.signal,
      }),
    ])
      .then(([currentAccount, currentStudent, scoreSummary]) => {
        if (!active) return;
        setAccount(currentAccount);
        setStudent(currentStudent);
        setSummary(scoreSummary);
        setIdentityError(null);
      })
      .catch((caught) => {
        if (!active || controller.signal.aborted) return;
        const message = handleError(caught, 'Không thể tải hồ sơ sinh viên.');
        if (message) setIdentityError(message);
      })
      .finally(() => {
        if (active) setIdentityLoading(false);
      });
    return () => { active = false; controller.abort(); };
  }, [handleError, identityReloadKey]);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    portalRequest<PageResponse<Score>>(queryPath('/api/students/me/scores', {
      keyword: filters.keyword,
      academicYear: filters.academicYear,
      semester: filters.semester,
      sort: filters.sort,
      page,
      size: 10,
    }), { signal: controller.signal })
      .then((result) => {
        if (!active) return;
        setScores(result);
        setScoresError(null);
      })
      .catch((caught) => {
        if (!active || controller.signal.aborted) return;
        const message = handleError(caught, 'Không thể tải bảng điểm. Vui lòng thử lại.');
        if (message) setScoresError(message);
      })
      .finally(() => {
        if (active) setScoresLoading(false);
      });
    return () => { active = false; controller.abort(); };
  }, [filters, handleError, page, scoresReloadKey]);

  const displayName = useMemo(() => {
    const fullName = `${student?.lastName ?? account?.lastName ?? ''} ${student?.firstName ?? account?.firstName ?? ''}`.trim();
    return fullName || account?.username || username;
  }, [account, student, username]);
  const accountName = account?.username ?? username;
  const initials = `${student?.lastName?.charAt(0) ?? ''}${student?.firstName?.charAt(0) ?? ''}`
    .toUpperCase() || accountName.slice(0, 2).toUpperCase() || 'SV';
  const latestTerm = summary?.latestAcademicYear && summary.latestSemester
    ? `HK ${summary.latestSemester} · ${summary.latestAcademicYear}`
    : 'Chưa có học kỳ';

  const submitFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setScoresLoading(true);
    setScoresError(null);
    setPage(0);
    setFilters({
      ...draftFilters,
      keyword: draftFilters.keyword.trim(),
      academicYear: draftFilters.academicYear.trim(),
    });
  };

  const clearFilters = () => {
    setScoresLoading(true);
    setScoresError(null);
    setDraftFilters(INITIAL_FILTERS);
    setFilters(INITIAL_FILTERS);
    setPage(0);
  };

  return (
    <main className="student-shell">
      <aside className={`sidebar student-sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <span className="brand-mark"><ShieldCheck aria-hidden="true" size={21} /></span>
          <div><strong>ZeroTrust</strong><span>Academic Portal</span></div>
        </div>

        <div className="nav-label">Không gian sinh viên</div>
        <nav aria-label="Điều hướng sinh viên">
          <a className="nav-item nav-item-active" href="#overview" onClick={() => setMobileNavOpen(false)}>
            <span className="nav-code"><GraduationCap aria-hidden="true" size={18} /></span>
            <span>Tổng quan học tập</span>
          </a>
          <a className="nav-item" href="#student-profile" onClick={() => setMobileNavOpen(false)}>
            <span className="nav-code"><CircleUserRound aria-hidden="true" size={18} /></span>
            <span>Hồ sơ cá nhân</span>
          </a>
          <a className="nav-item" href="#score-table" onClick={() => setMobileNavOpen(false)}>
            <span className="nav-code"><BookOpenCheck aria-hidden="true" size={18} /></span>
            <span>Bảng điểm</span>
          </a>
        </nav>

        <div className="student-session-card">
          <ShieldCheck aria-hidden="true" size={18} />
          <div><strong>Phiên được bảo vệ</strong><span>Keycloak · PKCE S256</span></div>
        </div>
      </aside>

      {mobileNavOpen && <button aria-label="Đóng menu" className="sidebar-backdrop" onClick={() => setMobileNavOpen(false)} type="button" />}

      <section className="workspace">
        <header className="topbar">
          <button aria-label="Mở menu" className="menu-button" onClick={() => setMobileNavOpen(true)} type="button"><Menu aria-hidden="true" size={20} /></button>
          <div className="topbar-title"><span>Không gian sinh viên</span><strong>Kết quả học tập</strong></div>
          <div className="topbar-actions">
            <div className="profile"><span className="avatar student-avatar">{initials}</span><div><strong>{accountName}</strong><span>STUDENT</span></div></div>
            <button aria-label="Đăng xuất" className="logout-button" onClick={onLogout} type="button"><LogOut aria-hidden="true" size={18} /></button>
          </div>
        </header>

        <div className="content student-content">
          {identityError && (
            <div className="student-profile-error" role="alert">
              <TriangleAlert aria-hidden="true" size={19} />
              <div><strong>Chưa tải được hồ sơ</strong><span>{identityError}</span></div>
              <button onClick={() => { setIdentityLoading(true); setIdentityError(null); setIdentityReloadKey((key) => key + 1); }} type="button"><RefreshCw aria-hidden="true" size={16} /> Thử lại</button>
            </div>
          )}

          <section className="student-hero" id="overview" aria-labelledby="student-heading">
            <div>
              <p className="eyebrow">Hồ sơ học tập cá nhân</p>
              <h1 id="student-heading">Xin chào, <span>{identityLoading ? accountName : displayName}</span></h1>
              <div className="student-identity-line"><span>Mã sinh viên</span><strong>{student?.studentCode ?? (identityLoading ? 'Đang tải…' : 'Chưa cập nhật')}</strong></div>
            </div>
            <div className="latest-term-card">
              <span className="latest-term-icon"><CalendarDays aria-hidden="true" size={21} /></span>
              <p>Kỳ học mới nhất</p><strong>{identityLoading ? 'Đang tải…' : latestTerm}</strong>
              <small>Tính trên toàn bộ kết quả hiện có, không phụ thuộc trang bảng điểm đang mở.</small>
            </div>
          </section>

          <section className="student-stats" aria-label="Tổng quan điểm số">
            <article><span className="metric-icon metric-coral"><BookOpenCheck aria-hidden="true" size={19} /></span><div><p>Tổng số môn</p><strong>{summary?.totalSubjects ?? '—'}</strong><small>{summary?.completedSubjects ?? 0} môn đã đủ điểm</small></div></article>
            <article><span className="metric-icon metric-teal"><GraduationCap aria-hidden="true" size={19} /></span><div><p>Điểm trung bình</p><strong>{formatScore(summary?.averageScore ?? null)}</strong><small>Của toàn bộ môn đã có tổng kết</small></div></article>
            <article><span className="metric-icon metric-blue"><CheckCircle2 aria-hidden="true" size={19} /></span><div><p>Đã qua môn</p><strong>{summary?.passedSubjects ?? '—'}</strong><small>Điểm tổng kết từ 4,0 trở lên</small></div></article>
            <article className={summary?.failedSubjects ? 'student-failed-stat' : undefined}><span className="metric-icon metric-red"><TriangleAlert aria-hidden="true" size={19} /></span><div><p>Trượt môn</p><strong>{summary?.failedSubjects ?? '—'}</strong><small>Điểm F dưới 4,0</small></div></article>
          </section>

          <section className="student-profile-panel" id="student-profile" aria-labelledby="student-profile-heading">
            <div className="student-profile-heading">
              <div><p className="eyebrow">Thông tin đã được xác thực</p><h2 id="student-profile-heading">Hồ sơ sinh viên</h2></div>
              <span className="student-profile-status"><ShieldCheck aria-hidden="true" size={15} /> {account?.status === 'ACTIVE' ? 'Đang hoạt động' : 'Đang kiểm tra'}</span>
            </div>
            <div className="student-profile-grid" aria-busy={identityLoading}>
              <ProfileField icon={<CircleUserRound size={18} />} label="Họ và tên" value={identityLoading ? 'Đang tải…' : displayName} />
              <ProfileField icon={<GraduationCap size={18} />} label="Mã sinh viên" value={student?.studentCode} />
              <ProfileField icon={<School size={18} />} label="Lớp" value={student ? `${student.classCode} · ${student.className}` : null} />
              <ProfileField icon={<Mail size={18} />} label="Email" value={account?.email ?? student?.email} />
              <ProfileField icon={<CalendarDays size={18} />} label="Ngày sinh" value={formatDate(student?.dateOfBirth)} />
              <ProfileField icon={<CircleUserRound size={18} />} label="Giới tính" value={genderLabel(student?.gender)} />
              <ProfileField icon={<Phone size={18} />} label="Số điện thoại" value={student?.phone} />
              <ProfileField icon={<MapPin size={18} />} label="Địa chỉ" value={student?.address} />
            </div>
            <p className="student-profile-note">Thông tin hồ sơ chỉ được xem tại đây. Nếu có sai sót, sinh viên liên hệ quản trị viên để cập nhật.</p>
          </section>

          <section className="scores-panel" id="score-table" aria-labelledby="scores-heading">
            <div className="scores-panel-heading"><div><p className="eyebrow">Chi tiết học phần</p><h2 id="scores-heading">Kết quả theo môn học</h2></div><span>{scores.totalElements} kết quả</span></div>
            <form className="score-filters" onSubmit={submitFilters}>
              <label><span>Tìm môn học</span><input maxLength={100} placeholder="Mã hoặc tên môn" value={draftFilters.keyword} onChange={(event) => setDraftFilters((current) => ({ ...current, keyword: event.target.value }))} /></label>
              <label><span>Học kỳ</span><select value={draftFilters.semester} onChange={(event) => setDraftFilters((current) => ({ ...current, semester: event.target.value }))}><option value="">Tất cả học kỳ</option><option value="1">Học kỳ 1</option><option value="2">Học kỳ 2</option></select></label>
              <label><span>Năm học</span><select value={draftFilters.academicYear} onChange={(event) => setDraftFilters((current) => ({ ...current, academicYear: event.target.value }))}><option value="">Tất cả năm học</option>{ACADEMIC_YEARS.map((year) => <option key={year} value={year}>{year}</option>)}</select></label>
              <label><span>Sắp xếp</span><select value={draftFilters.sort} onChange={(event) => setDraftFilters((current) => ({ ...current, sort: event.target.value }))}><option value="academicYear,desc">Năm học mới nhất</option><option value="academicYear,asc">Năm học cũ nhất</option><option value="subjectCode,asc">Mã môn A–Z</option><option value="totalScore,desc">Điểm cao nhất</option></select></label>
              <div className="filter-actions"><button className="filter-primary" disabled={scoresLoading} type="submit"><Search aria-hidden="true" size={17} /> Lọc kết quả</button><button className="filter-secondary" disabled={scoresLoading} onClick={clearFilters} type="button">Đặt lại</button></div>
            </form>

            {scoresError ? (
              <div className="scores-error" role="alert"><div><strong>Chưa tải được bảng điểm</strong><p>{scoresError}</p></div><button onClick={() => { setScoresLoading(true); setScoresError(null); setScoresReloadKey((key) => key + 1); }} type="button"><RefreshCw aria-hidden="true" size={16} /> Thử lại</button></div>
            ) : (
              <div className="score-table-wrap" aria-busy={scoresLoading}>
                <table className="score-table">
                  <thead><tr><th scope="col">Môn học</th><th scope="col">Học kỳ</th><th scope="col">Chuyên cần</th><th scope="col">Giữa kỳ</th><th scope="col">Cuối kỳ</th><th scope="col">Tổng kết</th><th scope="col">Điểm chữ</th></tr></thead>
                  <tbody>
                    {scoresLoading ? Array.from({ length: 5 }, (_, index) => <tr className="score-skeleton-row" key={index}><td colSpan={7}><span /></td></tr>) : scores.content.length ? scores.content.map((score) => {
                      const failed = score.grade?.toUpperCase() === 'F';
                      return (
                        <tr className={failed ? 'student-score-failed-row' : undefined} key={score.id}>
                          <td><strong>{score.subjectName}</strong><span>{score.subjectCode} · {score.academicYear}</span></td>
                          <td><span className="semester-badge">HK {score.semester}</span></td>
                          <td className="score-number">{formatScore(score.attendanceScore)}</td>
                          <td className="score-number">{formatScore(score.midtermScore)}</td>
                          <td className="score-number">{formatScore(score.finalScore)}</td>
                          <td className={`score-number score-total ${failed ? 'score-failed-text' : ''}`}>{formatScore(score.totalScore)}</td>
                          <td><span className={`grade-badge ${scoreGradeTone(score.grade)}`}>{score.grade ?? '—'}</span></td>
                        </tr>
                      );
                    }) : <tr><td colSpan={7}><div className="scores-empty"><BookOpenCheck aria-hidden="true" size={27} /><strong>Chưa có kết quả phù hợp</strong><span>Thử thay đổi môn học, học kỳ hoặc năm học đang lọc.</span></div></td></tr>}
                  </tbody>
                </table>
              </div>
            )}

            {!scoresError && !scoresLoading && scores.totalPages > 0 && <div className="score-pagination" aria-label="Phân trang bảng điểm"><p>{scores.totalElements} kết quả · Trang <strong>{scores.page + 1}</strong>/{scores.totalPages}</p><div><button aria-label="Trang trước" disabled={scores.first} onClick={() => { setScoresLoading(true); setPage((current) => Math.max(0, current - 1)); }} type="button"><ChevronLeft aria-hidden="true" size={17} /> Trước</button><button aria-label="Trang sau" disabled={scores.last} onClick={() => { setScoresLoading(true); setPage((current) => current + 1); }} type="button">Sau <ChevronRight aria-hidden="true" size={17} /></button></div></div>}
          </section>
        </div>
      </section>
    </main>
  );
}

function ProfileField({ icon, label, value }: { icon: ReactNode; label: string; value: string | null | undefined }) {
  return (
    <div className="student-profile-field">
      <span>{icon}</span>
      <div><small>{label}</small><strong>{value?.trim() || 'Chưa cập nhật'}</strong></div>
    </div>
  );
}
