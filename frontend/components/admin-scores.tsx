'use client';

import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import { BookOpenCheck, ClipboardCheck, Pencil, Plus, Search, Trash2, UserRoundSearch, UsersRound } from 'lucide-react';
import { AuthenticationExpiredError } from '../lib/api';
import {
  adminRequest,
  emptyPage,
  PageResponse,
  queryPath,
  Score,
  Student,
  Subject,
} from '../lib/admin-api';
import { academicYearOptions, currentAcademicYear } from '../lib/academic-years';
import { calculateScoreResult, formatScore, scoreGradeTone } from '../lib/score-calculation';
import { SubjectScoreSheet } from './admin-subject-score-sheet';
import {
  EmptyState,
  FormAlert,
  Modal,
  Pagination,
  PanelError,
  SubmitButton,
  TableSkeleton,
} from './admin-ui';

type ScoresPanelProps = {
  initialStudent: Student | null;
  onAuthenticationExpired: () => void;
  onNotify: (message: string) => void;
};

type ScoreFilters = {
  subjectId: string;
  semester: string;
  academicYear: string;
  sort: string;
};

const INITIAL_FILTERS: ScoreFilters = {
  subjectId: '',
  semester: '',
  academicYear: '',
  sort: 'academicYear,desc',
};
const ACADEMIC_YEARS = academicYearOptions();

export function ScoresPanel({ initialStudent, onAuthenticationExpired, onNotify }: ScoresPanelProps) {
  const [mode, setMode] = useState<'student' | 'subject'>('student');
  const [students, setStudents] = useState<Student[]>(initialStudent ? [initialStudent] : []);
  const [subjects, setSubjects] = useState<Subject[]>([]);
  const [studentId, setStudentId] = useState(initialStudent?.id ?? '');
  const [studentKeyword, setStudentKeyword] = useState('');
  const [draftFilters, setDraftFilters] = useState<ScoreFilters>(INITIAL_FILTERS);
  const [filters, setFilters] = useState<ScoreFilters>(INITIAL_FILTERS);
  const [scores, setScores] = useState<PageResponse<Score>>(emptyPage());
  const [page, setPage] = useState(0);
  const [reloadKey, setReloadKey] = useState(0);
  const [optionsLoading, setOptionsLoading] = useState(true);
  const [loading, setLoading] = useState(Boolean(initialStudent));
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [editingScore, setEditingScore] = useState<Score | null>(null);
  const [updateBusy, setUpdateBusy] = useState(false);
  const [updateError, setUpdateError] = useState<string | null>(null);
  const [deletingScore, setDeletingScore] = useState<Score | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const handleError = useCallback((caught: unknown, fallback: string): string | null => {
    if (caught instanceof AuthenticationExpiredError) {
      onAuthenticationExpired();
      return null;
    }
    return caught instanceof Error ? caught.message : fallback;
  }, [onAuthenticationExpired]);

  useEffect(() => {
    let active = true;
    Promise.all([
      adminRequest<PageResponse<Student>>('/api/admin/students?page=0&size=100&sort=studentCode,asc'),
      adminRequest<PageResponse<Subject>>('/api/admin/subjects?page=0&size=100&sort=subjectCode,asc'),
    ])
      .then(([studentPage, subjectPage]) => {
        if (!active) return;
        setStudents(studentPage.content);
        setSubjects(subjectPage.content);
        if (initialStudent && !studentPage.content.some((student) => student.id === initialStudent.id)) {
          setStudents([initialStudent, ...studentPage.content]);
        }
      })
      .catch((caught) => {
        const message = handleError(caught, 'Không thể tải dữ liệu sinh viên và môn học.');
        if (active && message) setError(message);
      })
      .finally(() => active && setOptionsLoading(false));
    return () => { active = false; };
  }, [handleError, initialStudent]);

  useEffect(() => {
    if (!studentId) {
      return;
    }

    let active = true;
    const controller = new AbortController();
    adminRequest<PageResponse<Score>>(queryPath(`/api/admin/students/${studentId}/scores`, {
      ...filters,
      page,
      size: 10,
    }), { signal: controller.signal })
      .then((result) => active && setScores(result))
      .catch((caught) => {
        if (!active || controller.signal.aborted) return;
        const message = handleError(caught, 'Không thể tải bảng điểm.');
        if (message) setError(message);
      })
      .finally(() => active && setLoading(false));
    return () => { active = false; controller.abort(); };
  }, [filters, handleError, page, reloadKey, studentId]);

  const selectedStudent = students.find((student) => student.id === studentId) ?? initialStudent;
  const filteredStudents = useMemo(() => {
    const keyword = studentKeyword.trim().toLocaleLowerCase('vi');
    if (!keyword) return students;
    return students.filter((student) => [student.studentCode, student.username, student.firstName, student.lastName]
      .some((value) => value.toLocaleLowerCase('vi').includes(keyword)));
  }, [studentKeyword, students]);

  const summary = useMemo(() => {
    const totals = scores.content.map((score) => score.totalScore).filter((value): value is number => value !== null);
    return {
      completed: totals.length,
      average: totals.length ? totals.reduce((sum, value) => sum + value, 0) / totals.length : null,
      best: totals.length ? Math.max(...totals) : null,
    };
  }, [scores.content]);

  const selectStudent = (nextId: string) => {
    setScores(emptyPage());
    setLoading(Boolean(nextId));
    setError(null);
    setStudentId(nextId); setPage(0); setFilters(INITIAL_FILTERS); setDraftFilters(INITIAL_FILTERS);
  };

  const submitFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setLoading(true); setError(null); setPage(0);
    setFilters({ ...draftFilters, academicYear: draftFilters.academicYear.trim() });
  };

  const createScore = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!studentId) return;
    const form = event.currentTarget; const values = new FormData(form);
    setCreateBusy(true); setCreateError(null);
    try {
      await adminRequest<Score>(`/api/admin/students/${studentId}/scores`, {
        method: 'POST',
        body: JSON.stringify({
          subjectId: String(values.get('subjectId') ?? ''),
          semester: Number(values.get('semester')),
          academicYear: String(values.get('academicYear') ?? '').trim(),
          attendanceScore: Number(values.get('attendanceScore')),
          midtermScore: Number(values.get('midtermScore')),
          finalScore: Number(values.get('finalScore')),
        }),
      });
      form.reset(); setCreateOpen(false); setLoading(true); setError(null); setReloadKey((value) => value + 1);
      onNotify(`Đã thêm điểm cho sinh viên ${selectedStudent?.studentCode ?? ''}.`);
    } catch (caught) {
      const message = handleError(caught, 'Không thể thêm điểm.');
      if (message) setCreateError(message);
    } finally { setCreateBusy(false); }
  };

  const updateScore = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!editingScore) return;
    const values = new FormData(event.currentTarget);
    const body: Record<string, string | number> = {
      subjectId: String(values.get('subjectId') ?? ''),
      semester: Number(values.get('semester')),
      academicYear: String(values.get('academicYear') ?? '').trim(),
      attendanceScore: Number(values.get('attendanceScore')),
      midtermScore: Number(values.get('midtermScore')),
      finalScore: Number(values.get('finalScore')),
    };

    setUpdateBusy(true); setUpdateError(null);
    try {
      const updated = await adminRequest<Score>(`/api/admin/scores/${editingScore.id}`, {
        method: 'PATCH', body: JSON.stringify(body),
      });
      setEditingScore(updated); setLoading(true); setError(null); setReloadKey((value) => value + 1);
      onNotify('Cập nhật điểm thành công.');
    } catch (caught) {
      const message = handleError(caught, 'Không thể cập nhật điểm.');
      if (message) setUpdateError(message);
    } finally { setUpdateBusy(false); }
  };

  const deleteScore = async () => {
    if (!deletingScore) return;
    setDeleteBusy(true); setDeleteError(null);
    try {
      await adminRequest<void>(`/api/admin/scores/${deletingScore.id}`, {
        method: 'DELETE',
      });
      const deletedSubjectCode = deletingScore.subjectCode;
      setDeletingScore(null); setLoading(true); setError(null);
      if (scores.content.length === 1 && page > 0) setPage((current) => current - 1);
      setReloadKey((value) => value + 1);
      onNotify(`Đã xóa điểm môn ${deletedSubjectCode}.`);
    } catch (caught) {
      const message = handleError(caught, 'Không thể xóa điểm.');
      if (message) setDeleteError(message);
    } finally { setDeleteBusy(false); }
  };

  return (
    <>
      <section className="admin-page-heading">
        <div><p className="eyebrow">Kết quả học tập</p><h1>Quản lý điểm</h1><p>Nhập từng sinh viên hoặc cập nhật nhanh cả danh sách theo môn học và lớp.</p></div>
        {mode === 'student' && <button className="admin-primary-button" disabled={!studentId} onClick={() => setCreateOpen(true)} type="button"><Plus aria-hidden="true" size={17} /> Nhập điểm</button>}
      </section>

      <div className="score-mode-tabs" role="tablist" aria-label="Cách nhập điểm">
        <button aria-selected={mode === 'student'} className={mode === 'student' ? 'active' : undefined} onClick={() => setMode('student')} role="tab" type="button"><UsersRound aria-hidden="true" size={17} /> Theo sinh viên</button>
        <button aria-selected={mode === 'subject'} className={mode === 'subject' ? 'active' : undefined} onClick={() => setMode('subject')} role="tab" type="button"><BookOpenCheck aria-hidden="true" size={17} /> Theo môn học</button>
      </div>

      {mode === 'student' ? <>
      <section className="score-student-picker">
        <div className="picker-title"><span><UserRoundSearch aria-hidden="true" size={20} /></span><div><strong>Chọn sinh viên</strong><small>Bảng điểm được truy vấn theo ID nội bộ, bạn không cần nhớ UUID.</small></div></div>
        <div className="score-picker-controls">
          <div className="admin-input-icon"><Search aria-hidden="true" size={16} /><input aria-label="Lọc danh sách sinh viên" placeholder="Lọc nhanh sinh viên" value={studentKeyword} onChange={(event) => setStudentKeyword(event.target.value)} /></div>
          <select aria-label="Chọn sinh viên" disabled={optionsLoading} value={studentId} onChange={(event) => selectStudent(event.target.value)}>
            <option value="">Chọn sinh viên…</option>
            {filteredStudents.map((student) => <option key={student.id} value={student.id}>{student.studentCode} · {student.lastName} {student.firstName}</option>)}
          </select>
        </div>
      </section>

      {studentId && selectedStudent && (
        <section className="score-admin-summary">
          <article className="selected-student-card"><span>{selectedStudent.firstName.charAt(0)}{selectedStudent.lastName.charAt(0)}</span><div><p>Sinh viên đang xem</p><strong>{selectedStudent.lastName} {selectedStudent.firstName}</strong><small>{selectedStudent.studentCode} · {selectedStudent.classCode}</small></div></article>
          <article><p>Tổng kết quả</p><strong>{scores.totalElements}</strong><small>Theo bộ lọc hiện tại</small></article>
          <article><p>Điểm trung bình</p><strong>{formatScore(summary.average)}</strong><small>{summary.completed} môn có điểm tổng</small></article>
          <article><p>Điểm cao nhất</p><strong>{formatScore(summary.best)}</strong><small>Trên trang đang xem</small></article>
        </section>
      )}

      <section className="admin-data-panel">
        {!studentId ? <EmptyState title="Hãy chọn một sinh viên" description="Sau khi chọn, danh sách điểm và nút nhập điểm sẽ được bật." /> : <>
          <form className="admin-filters admin-filters-four" onSubmit={submitFilters}>
            <label><span>Môn học</span><select value={draftFilters.subjectId} onChange={(event) => setDraftFilters((current) => ({ ...current, subjectId: event.target.value }))}><option value="">Tất cả môn</option>{subjects.map((subject) => <option key={subject.id} value={subject.id}>{subject.subjectCode} · {subject.subjectName}</option>)}</select></label>
            <label><span>Học kỳ</span><select value={draftFilters.semester} onChange={(event) => setDraftFilters((current) => ({ ...current, semester: event.target.value }))}><option value="">Tất cả</option><option value="1">Học kỳ 1</option><option value="2">Học kỳ 2</option></select></label>
            <label><span>Năm học</span><select value={draftFilters.academicYear} onChange={(event) => setDraftFilters((current) => ({ ...current, academicYear: event.target.value }))}><option value="">Tất cả năm học</option>{ACADEMIC_YEARS.map((year) => <option key={year} value={year}>{year}</option>)}</select></label>
            <label><span>Sắp xếp</span><select value={draftFilters.sort} onChange={(event) => setDraftFilters((current) => ({ ...current, sort: event.target.value }))}><option value="academicYear,desc">Năm học mới nhất</option><option value="subjectCode,asc">Mã môn A–Z</option><option value="semester,asc">Học kỳ tăng dần</option><option value="totalScore,desc">Điểm cao nhất</option></select></label>
            <div className="admin-filter-actions"><button className="admin-secondary-button" disabled={loading} type="submit">Lọc dữ liệu</button><button className="admin-text-button" disabled={loading} onClick={() => { setLoading(true); setError(null); setDraftFilters(INITIAL_FILTERS); setFilters({ ...INITIAL_FILTERS }); setPage(0); }} type="button">Đặt lại</button></div>
          </form>
          {error ? <PanelError message={error} onRetry={() => { setLoading(true); setError(null); setReloadKey((value) => value + 1); }} /> : <div className="admin-table-wrap" aria-busy={loading}><table className="admin-table admin-score-table"><thead><tr><th>Môn học</th><th>Học kỳ</th><th>CC</th><th>GK</th><th>CK</th><th>Tổng</th><th>Chữ</th><th aria-label="Thao tác" /></tr></thead><tbody>{loading ? <TableSkeleton columns={8} /> : scores.content.length ? scores.content.map((score) => <tr key={score.id}><td><strong className="admin-cell-main">{score.subjectName}</strong><small>{score.subjectCode} · {score.academicYear}</small></td><td><span className="semester-badge">HK {score.semester}</span></td><td className="score-number">{formatScore(score.attendanceScore)}</td><td className="score-number">{formatScore(score.midtermScore)}</td><td className="score-number">{formatScore(score.finalScore)}</td><td className="score-number score-total">{formatScore(score.totalScore)}</td><td><span className={`grade-badge ${scoreGradeTone(score.grade)}`}>{score.grade ?? '—'}</span></td><td><div className="admin-row-actions"><button aria-label={`Sửa điểm môn ${score.subjectCode}`} title="Sửa điểm" onClick={() => { setEditingScore(score); setUpdateError(null); }} type="button"><Pencil aria-hidden="true" size={15} /></button><button aria-label={`Xóa điểm môn ${score.subjectCode}`} className="admin-danger-icon" title="Xóa điểm" onClick={() => { setDeletingScore(score); setDeleteError(null); }} type="button"><Trash2 aria-hidden="true" size={15} /></button></div></td></tr>) : <tr><td colSpan={8}><EmptyState title="Chưa có kết quả phù hợp" description="Thêm điểm mới hoặc thay đổi bộ lọc." /></td></tr>}</tbody></table></div>}
          {!error && !loading && <Pagination {...scores} onPageChange={(nextPage) => { setLoading(true); setError(null); setPage(nextPage); }} />}
        </>}
      </section>

      {createOpen && selectedStudent && <Modal eyebrow={`Sinh viên ${selectedStudent.studentCode}`} title="Nhập kết quả môn học" description="Mỗi sinh viên chỉ có một kết quả cho mỗi môn; tổng kết và điểm chữ được tự động tính." onClose={() => { if (!createBusy) setCreateOpen(false); }} wide>
        <form className="admin-form" onSubmit={createScore}><FormAlert message={createError} /><ScoreFields subjects={subjects} /><div className="admin-form-footer"><button className="admin-text-button" disabled={createBusy} onClick={() => setCreateOpen(false)} type="button">Hủy</button><SubmitButton busy={createBusy}><ClipboardCheck aria-hidden="true" size={17} /> Lưu điểm</SubmitButton></div></form>
      </Modal>}

      {editingScore && <Modal eyebrow={`${editingScore.studentCode} · ${editingScore.subjectCode}`} title="Cập nhật điểm" description="Sau khi lưu, tổng kết và điểm chữ sẽ được tính lại từ ba đầu điểm." onClose={() => { if (!updateBusy) setEditingScore(null); }} wide>
        <form className="admin-form" key={editingScore.id} onSubmit={updateScore}><FormAlert message={updateError} /><ScoreFields score={editingScore} subjects={subjects} /><div className="admin-form-footer"><button className="admin-text-button" disabled={updateBusy} onClick={() => setEditingScore(null)} type="button">Đóng</button><SubmitButton busy={updateBusy}><Pencil aria-hidden="true" size={16} /> Lưu thay đổi</SubmitButton></div></form>
      </Modal>}

      {deletingScore && <Modal eyebrow={`${deletingScore.studentCode} · ${deletingScore.subjectCode}`} title="Xóa điểm sinh viên?" description="Bản ghi điểm sẽ bị xóa khỏi hệ thống và không thể hoàn tác." onClose={() => { if (!deleteBusy) setDeletingScore(null); }}>
        <div className="admin-delete-confirmation"><FormAlert message={deleteError} /><p>Bạn đang xóa điểm môn <strong>{deletingScore.subjectName}</strong>, học kỳ {deletingScore.semester}, năm học {deletingScore.academicYear}.</p><div className="admin-form-footer"><button className="admin-text-button" disabled={deleteBusy} onClick={() => setDeletingScore(null)} type="button">Hủy</button><button className="admin-primary-button admin-danger-button" disabled={deleteBusy} onClick={() => void deleteScore()} type="button"><Trash2 aria-hidden="true" size={16} /> {deleteBusy ? 'Đang xóa…' : 'Xóa điểm'}</button></div></div>
      </Modal>}
      </> : <SubjectScoreSheet optionsLoading={optionsLoading} subjects={subjects} onAuthenticationExpired={onAuthenticationExpired} onNotify={onNotify} />}
    </>
  );
}

function ScoreFields({ subjects, score }: { subjects: Subject[]; score?: Score }) {
  const [attendance, setAttendance] = useState(score?.attendanceScore?.toString() ?? '');
  const [midterm, setMidterm] = useState(score?.midtermScore?.toString() ?? '');
  const [finalScore, setFinalScore] = useState(score?.finalScore?.toString() ?? '');
  const result = useMemo(
    () => calculateScoreResult(attendance, midterm, finalScore),
    [attendance, finalScore, midterm],
  );
  const academicYears = academicYearOptions(score?.academicYear);

  return (
    <div className="admin-form-grid score-form-grid">
      <label className="admin-field-wide"><span>Môn học *</span><select defaultValue={score?.subjectId ?? ''} name="subjectId" required><option disabled value="">Chọn môn học</option>{subjects.map((subject) => <option key={subject.id} value={subject.id}>{subject.subjectCode} · {subject.subjectName} ({subject.credits} TC)</option>)}</select></label>
      <label><span>Học kỳ *</span><select defaultValue={score?.semester ?? '1'} name="semester" required><option value="1">Học kỳ 1</option><option value="2">Học kỳ 2</option></select></label>
      <label><span>Năm học *</span><select defaultValue={score?.academicYear ?? currentAcademicYear()} name="academicYear" required>{academicYears.map((year) => <option key={year} value={year}>{year}</option>)}</select></label>
      <label><span>Chuyên cần *</span><input max={10} min={0} name="attendanceScore" onChange={(event) => setAttendance(event.target.value)} required step="0.01" type="number" value={attendance} /></label>
      <label><span>Giữa kỳ *</span><input max={10} min={0} name="midtermScore" onChange={(event) => setMidterm(event.target.value)} required step="0.01" type="number" value={midterm} /></label>
      <label><span>Cuối kỳ *</span><input max={10} min={0} name="finalScore" onChange={(event) => setFinalScore(event.target.value)} required step="0.01" type="number" value={finalScore} /></label>
      <div className={`admin-calculated-score ${result?.grade === 'F' ? 'calculated-failed' : ''}`}>
        <div><span>Kết quả tự động</span><strong>{result ? formatScore(result.totalScore) : '—'}</strong></div>
        <span className={`grade-badge ${scoreGradeTone(result?.grade ?? null)}`}>{result?.grade ?? '—'}</span>
        <small>(GK × 0,7 + CC × 0,3) × 0,3 + CK × 0,7</small>
      </div>
    </div>
  );
}
