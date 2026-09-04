'use client';

import { FormEvent, useEffect, useMemo, useState } from 'react';
import {
  BookOpenCheck,
  CalendarDays,
  ChevronLeft,
  ChevronRight,
  GraduationCap,
  LogOut,
  Menu,
  RefreshCw,
  Search,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { apiFetch, AuthenticationExpiredError } from '../lib/api';

type Score = {
  id: string;
  studentId: string;
  studentCode: string;
  subjectId: string;
  subjectCode: string;
  subjectName: string;
  semester: number;
  academicYear: string;
  attendanceScore: number | null;
  midtermScore: number | null;
  finalScore: number | null;
  totalScore: number | null;
  grade: string | null;
};

type PageResponse<T> = {
  content: T[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
  first: boolean;
  last: boolean;
};

type ApiResponse<T> = {
  data: T;
  message: string;
  success: boolean;
};

type ScoreFilters = {
  academicYear: string;
  semester: string;
  sort: string;
};

type StudentScoreDashboardProps = {
  username: string;
  onLogout: () => void;
  onAuthenticationExpired: () => void;
};

const EMPTY_PAGE: PageResponse<Score> = {
  content: [],
  page: 0,
  size: 10,
  totalElements: 0,
  totalPages: 0,
  first: true,
  last: true,
};

const INITIAL_FILTERS: ScoreFilters = {
  academicYear: '',
  semester: '',
  sort: 'academicYear,desc',
};

function formatScore(value: number | null): string {
  if (value === null) return '—';
  return new Intl.NumberFormat('vi-VN', {
    minimumFractionDigits: Number.isInteger(value) ? 0 : 1,
    maximumFractionDigits: 2,
  }).format(value);
}

function gradeTone(grade: string | null): string {
  const firstLetter = grade?.trim().toUpperCase().charAt(0);
  if (firstLetter === 'A') return 'grade-excellent';
  if (firstLetter === 'B') return 'grade-good';
  if (firstLetter === 'C') return 'grade-average';
  if (firstLetter === 'D') return 'grade-warning';
  if (firstLetter === 'F') return 'grade-failed';
  return 'grade-pending';
}

function buildScoresPath(filters: ScoreFilters, page: number): string {
  const params = new URLSearchParams({
    page: String(page),
    size: '10',
    sort: filters.sort,
  });
  if (filters.semester) params.set('semester', filters.semester);
  if (filters.academicYear.trim()) params.set('academicYear', filters.academicYear.trim());
  return `/api/students/me/scores?${params.toString()}`;
}

export function StudentScoreDashboard({
  username,
  onLogout,
  onAuthenticationExpired,
}: StudentScoreDashboardProps) {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [draftFilters, setDraftFilters] = useState<ScoreFilters>(INITIAL_FILTERS);
  const [filters, setFilters] = useState<ScoreFilters>(INITIAL_FILTERS);
  const [page, setPage] = useState(0);
  const [scores, setScores] = useState<PageResponse<Score>>(EMPTY_PAGE);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();

    async function loadScores() {
      setLoading(true);
      setError(null);
      try {
        const response = await apiFetch(buildScoresPath(filters, page), {
          signal: controller.signal,
        });

        if (response.status === 401) {
          onAuthenticationExpired();
          return;
        }
        if (response.status === 403) {
          throw new Error('Tài khoản hiện tại không có quyền xem bảng điểm sinh viên.');
        }
        if (!response.ok) {
          const body = (await response.json().catch(() => null)) as { message?: unknown } | null;
          const message = typeof body?.message === 'string'
            ? body.message
            : 'Không thể tải bảng điểm. Vui lòng thử lại.';
          throw new Error(message);
        }

        const payload = (await response.json()) as ApiResponse<PageResponse<Score>>;
        if (active) setScores(payload.data);
      } catch (loadError) {
        if (!active || controller.signal.aborted) return;
        if (loadError instanceof AuthenticationExpiredError) {
          onAuthenticationExpired();
          return;
        }
        setError(
          loadError instanceof Error
            ? loadError.message
            : 'Không thể tải bảng điểm. Vui lòng thử lại.',
        );
      } finally {
        if (active) setLoading(false);
      }
    }

    void loadScores();
    return () => {
      active = false;
      controller.abort();
    };
  }, [filters, onAuthenticationExpired, page, reloadKey]);

  const summary = useMemo(() => {
    const totals = scores.content
      .map((score) => score.totalScore)
      .filter((score): score is number => score !== null);
    const average = totals.length
      ? totals.reduce((sum, score) => sum + score, 0) / totals.length
      : null;
    const best = totals.length ? Math.max(...totals) : null;
    const latest = scores.content[0];
    return {
      average,
      best,
      studentCode: latest?.studentCode ?? 'Chưa có dữ liệu',
      latestTerm: latest ? `HK ${latest.semester} · ${latest.academicYear}` : 'Chưa có học kỳ',
    };
  }, [scores.content]);

  const submitFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPage(0);
    setFilters({ ...draftFilters, academicYear: draftFilters.academicYear.trim() });
  };

  const clearFilters = () => {
    setDraftFilters(INITIAL_FILTERS);
    setFilters(INITIAL_FILTERS);
    setPage(0);
  };

  return (
    <main className="student-shell">
      <aside className={`sidebar student-sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <span className="brand-mark"><ShieldCheck aria-hidden="true" size={21} /></span>
          <div>
            <strong>ZeroTrust</strong>
            <span>Academic Portal</span>
          </div>
        </div>

        <div className="nav-label">Không gian sinh viên</div>
        <nav aria-label="Điều hướng sinh viên">
          <a className="nav-item nav-item-active" href="#overview" onClick={() => setMobileNavOpen(false)}>
            <span className="nav-code"><GraduationCap aria-hidden="true" size={18} /></span>
            <span>Tổng quan học tập</span>
          </a>
          <a className="nav-item" href="#score-table" onClick={() => setMobileNavOpen(false)}>
            <span className="nav-code"><BookOpenCheck aria-hidden="true" size={18} /></span>
            <span>Bảng điểm</span>
          </a>
        </nav>

        <div className="student-session-card">
          <ShieldCheck aria-hidden="true" size={18} />
          <div>
            <strong>Phiên được bảo vệ</strong>
            <span>Keycloak · PKCE S256</span>
          </div>
        </div>
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
            <span>Không gian sinh viên</span>
            <strong>Kết quả học tập</strong>
          </div>
          <div className="topbar-actions">
            <div className="profile">
              <span className="avatar student-avatar">{username.slice(0, 2).toUpperCase() || 'SV'}</span>
              <div>
                <strong>{username}</strong>
                <span>STUDENT</span>
              </div>
            </div>
            <button aria-label="Đăng xuất" className="logout-button" onClick={onLogout} type="button">
              <LogOut aria-hidden="true" size={18} />
            </button>
          </div>
        </header>

        <div className="content student-content">
          <section className="student-hero" id="overview" aria-labelledby="student-heading">
            <div>
              <p className="eyebrow">Hồ sơ học tập cá nhân</p>
              <h1 id="student-heading">Bảng điểm của <span>{username}</span></h1>
              <p>
                Theo dõi kết quả từng môn học. Dữ liệu chỉ được trả về khi access token
                có role STUDENT và thuộc đúng hồ sơ sinh viên đang đăng nhập.
              </p>
              <div className="student-identity-line">
                <span>Mã sinh viên</span>
                <strong>{summary.studentCode}</strong>
              </div>
            </div>
            <div className="latest-term-card">
              <span className="latest-term-icon"><CalendarDays aria-hidden="true" size={21} /></span>
              <p>Kỳ học mới nhất</p>
              <strong>{summary.latestTerm}</strong>
              <small>Cập nhật theo dữ liệu hiện có trong hệ thống</small>
            </div>
          </section>

          <section className="student-stats" aria-label="Tổng quan điểm số">
            <article>
              <span className="metric-icon metric-coral"><BookOpenCheck aria-hidden="true" size={19} /></span>
              <div>
                <p>Tổng kết quả</p>
                <strong>{scores.totalElements}</strong>
                <small>Bản ghi phù hợp bộ lọc</small>
              </div>
            </article>
            <article>
              <span className="metric-icon metric-teal"><GraduationCap aria-hidden="true" size={19} /></span>
              <div>
                <p>Điểm trung bình</p>
                <strong>{formatScore(summary.average)}</strong>
                <small>Trên trang đang xem</small>
              </div>
            </article>
            <article>
              <span className="metric-icon metric-blue"><Sparkles aria-hidden="true" size={19} /></span>
              <div>
                <p>Điểm cao nhất</p>
                <strong>{formatScore(summary.best)}</strong>
                <small>Trên trang đang xem</small>
              </div>
            </article>
          </section>

          <section className="scores-panel" id="score-table" aria-labelledby="scores-heading">
            <div className="scores-panel-heading">
              <div>
                <p className="eyebrow">Chi tiết học phần</p>
                <h2 id="scores-heading">Kết quả theo môn học</h2>
              </div>
              <span>{scores.totalElements} kết quả</span>
            </div>

            <form className="score-filters" onSubmit={submitFilters}>
              <label>
                <span>Học kỳ</span>
                <select
                  value={draftFilters.semester}
                  onChange={(event) => setDraftFilters((current) => ({
                    ...current,
                    semester: event.target.value,
                  }))}
                >
                  <option value="">Tất cả học kỳ</option>
                  <option value="1">Học kỳ 1</option>
                  <option value="2">Học kỳ 2</option>
                  <option value="3">Học kỳ 3</option>
                </select>
              </label>
              <label>
                <span>Năm học</span>
                <input
                  aria-describedby="academic-year-hint"
                  inputMode="numeric"
                  placeholder="Ví dụ: 2026-2027"
                  value={draftFilters.academicYear}
                  onChange={(event) => setDraftFilters((current) => ({
                    ...current,
                    academicYear: event.target.value,
                  }))}
                />
                <small id="academic-year-hint">Định dạng YYYY-YYYY</small>
              </label>
              <label>
                <span>Sắp xếp</span>
                <select
                  value={draftFilters.sort}
                  onChange={(event) => setDraftFilters((current) => ({
                    ...current,
                    sort: event.target.value,
                  }))}
                >
                  <option value="academicYear,desc">Năm học mới nhất</option>
                  <option value="academicYear,asc">Năm học cũ nhất</option>
                  <option value="subjectCode,asc">Mã môn A–Z</option>
                  <option value="totalScore,desc">Điểm cao nhất</option>
                </select>
              </label>
              <div className="filter-actions">
                <button className="filter-primary" disabled={loading} type="submit">
                  <Search aria-hidden="true" size={17} /> Lọc kết quả
                </button>
                <button className="filter-secondary" disabled={loading} onClick={clearFilters} type="button">
                  Đặt lại
                </button>
              </div>
            </form>

            {error ? (
              <div className="scores-error" role="alert">
                <div>
                  <strong>Chưa tải được bảng điểm</strong>
                  <p>{error}</p>
                </div>
                <button onClick={() => setReloadKey((key) => key + 1)} type="button">
                  <RefreshCw aria-hidden="true" size={16} /> Thử lại
                </button>
              </div>
            ) : (
              <div className="score-table-wrap" aria-busy={loading}>
                <table className="score-table">
                  <thead>
                    <tr>
                      <th scope="col">Môn học</th>
                      <th scope="col">Học kỳ</th>
                      <th scope="col">Chuyên cần</th>
                      <th scope="col">Giữa kỳ</th>
                      <th scope="col">Cuối kỳ</th>
                      <th scope="col">Tổng kết</th>
                      <th scope="col">Điểm chữ</th>
                    </tr>
                  </thead>
                  <tbody>
                    {loading ? (
                      Array.from({ length: 5 }, (_, index) => (
                        <tr className="score-skeleton-row" key={index}>
                          <td colSpan={7}><span /></td>
                        </tr>
                      ))
                    ) : scores.content.length ? (
                      scores.content.map((score) => (
                        <tr key={score.id}>
                          <td>
                            <strong>{score.subjectName}</strong>
                            <span>{score.subjectCode} · {score.academicYear}</span>
                          </td>
                          <td><span className="semester-badge">HK {score.semester}</span></td>
                          <td className="score-number">{formatScore(score.attendanceScore)}</td>
                          <td className="score-number">{formatScore(score.midtermScore)}</td>
                          <td className="score-number">{formatScore(score.finalScore)}</td>
                          <td className="score-number score-total">{formatScore(score.totalScore)}</td>
                          <td>
                            <span className={`grade-badge ${gradeTone(score.grade)}`}>
                              {score.grade ?? '—'}
                            </span>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={7}>
                          <div className="scores-empty">
                            <BookOpenCheck aria-hidden="true" size={27} />
                            <strong>Chưa có kết quả phù hợp</strong>
                            <span>Thử thay đổi học kỳ hoặc năm học đang lọc.</span>
                          </div>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {!error && !loading && scores.totalPages > 0 && (
              <div className="score-pagination" aria-label="Phân trang bảng điểm">
                <p>Trang <strong>{scores.page + 1}</strong> / {scores.totalPages}</p>
                <div>
                  <button
                    aria-label="Trang trước"
                    disabled={scores.first}
                    onClick={() => setPage((current) => Math.max(0, current - 1))}
                    type="button"
                  >
                    <ChevronLeft aria-hidden="true" size={17} /> Trước
                  </button>
                  <button
                    aria-label="Trang sau"
                    disabled={scores.last}
                    onClick={() => setPage((current) => current + 1)}
                    type="button"
                  >
                    Sau <ChevronRight aria-hidden="true" size={17} />
                  </button>
                </div>
              </div>
            )}
          </section>
        </div>
      </section>
    </main>
  );
}
