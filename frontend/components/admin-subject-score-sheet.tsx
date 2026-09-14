'use client';

import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import { BookOpenCheck, Save, Search, UsersRound } from 'lucide-react';
import { AuthenticationExpiredError } from '../lib/api';
import {
  adminRequest,
  BatchScoreResult,
  emptyPage,
  PageResponse,
  queryPath,
  StudentClass,
  Subject,
  SubjectScoreSheetRow,
} from '../lib/admin-api';
import {
  calculateScoreResult,
  formatScore,
  isValidScoreInput,
  scoreGradeTone,
} from '../lib/score-calculation';
import { academicYearOptions, currentAcademicYear } from '../lib/academic-years';
import { EmptyState, FormAlert, Pagination, PanelError, TableSkeleton } from './admin-ui';

type SubjectScoreSheetProps = {
  subjects: Subject[];
  optionsLoading: boolean;
  onAuthenticationExpired: () => void;
  onNotify: (message: string) => void;
};

type SheetControls = {
  subjectId: string;
  classCode: string;
  semester: string;
  academicYear: string;
  keyword: string;
};

type ScoreDraft = {
  attendanceScore: string;
  midtermScore: string;
  finalScore: string;
};

const PAGE_SIZE = 100;
const ACADEMIC_YEARS = academicYearOptions();

function toDraft(row: SubjectScoreSheetRow): ScoreDraft {
  return {
    attendanceScore: row.attendanceScore?.toString() ?? '',
    midtermScore: row.midtermScore?.toString() ?? '',
    finalScore: row.finalScore?.toString() ?? '',
  };
}

export function SubjectScoreSheet({
  subjects,
  optionsLoading,
  onAuthenticationExpired,
  onNotify,
}: SubjectScoreSheetProps) {
  const [classes, setClasses] = useState<StudentClass[]>([]);
  const [controls, setControls] = useState<SheetControls>({
    subjectId: '',
    classCode: '',
    semester: '1',
    academicYear: currentAcademicYear(),
    keyword: '',
  });
  const [query, setQuery] = useState<SheetControls | null>(null);
  const [sheet, setSheet] = useState<PageResponse<SubjectScoreSheetRow>>(emptyPage(PAGE_SIZE));
  const [drafts, setDrafts] = useState<Record<string, ScoreDraft>>({});
  const [dirtyIds, setDirtyIds] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(0);
  const [reloadKey, setReloadKey] = useState(0);
  const [classesLoading, setClassesLoading] = useState(true);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const handleError = useCallback((caught: unknown, fallback: string): string | null => {
    if (caught instanceof AuthenticationExpiredError) {
      onAuthenticationExpired();
      return null;
    }
    return caught instanceof Error ? caught.message : fallback;
  }, [onAuthenticationExpired]);

  useEffect(() => {
    let active = true;
    adminRequest<PageResponse<StudentClass>>(
      '/api/admin/student-classes?page=0&size=100&sort=classCode,asc',
    )
      .then((result) => {
        if (active) setClasses(result.content);
      })
      .catch((caught) => {
        const message = handleError(caught, 'Không thể tải danh sách lớp.');
        if (active && message) setError(message);
      })
      .finally(() => {
        if (active) setClassesLoading(false);
      });
    return () => { active = false; };
  }, [handleError]);

  useEffect(() => {
    if (!query) return;

    let active = true;
    const controller = new AbortController();
    adminRequest<PageResponse<SubjectScoreSheetRow>>(queryPath(
      `/api/admin/subjects/${query.subjectId}/score-sheet`,
      {
        classCode: query.classCode,
        keyword: query.keyword,
        page,
        size: PAGE_SIZE,
      },
    ), { signal: controller.signal })
      .then((result) => {
        if (!active) return;
        setSheet(result);
        setDrafts(Object.fromEntries(result.content.map((row) => [row.studentId, toDraft(row)])));
        setDirtyIds(new Set());
      })
      .catch((caught) => {
        if (!active || controller.signal.aborted) return;
        const message = handleError(caught, 'Không thể tải danh sách nhập điểm.');
        if (message) setError(message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => { active = false; controller.abort(); };
  }, [handleError, page, query, reloadKey]);

  const selectedSubject = useMemo(
    () => subjects.find((subject) => subject.id === query?.subjectId),
    [query?.subjectId, subjects],
  );
  const selectedClass = useMemo(
    () => classes.find((studentClass) => studentClass.classCode === query?.classCode),
    [classes, query?.classCode],
  );

  const loadSheet = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (dirtyIds.size > 0 && !window.confirm('Điểm chưa lưu sẽ bị bỏ. Bạn vẫn muốn tải danh sách khác?')) {
      return;
    }
    setError(null);
    setSaveError(null);
    setLoading(true);
    setPage(0);
    setQuery({
      ...controls,
      academicYear: controls.academicYear.trim(),
      keyword: controls.keyword.trim(),
    });
  };

  const updateDraft = (studentId: string, field: keyof ScoreDraft, value: string) => {
    setDrafts((current) => ({
      ...current,
      [studentId]: { ...current[studentId], [field]: value },
    }));
    setDirtyIds((current) => {
      const updated = new Set(current);
      updated.add(studentId);
      return updated;
    });
    setSaveError(null);
  };

  const saveScores = async () => {
    if (!query || dirtyIds.size === 0) return;
    const changedRows = sheet.content.filter((row) => dirtyIds.has(row.studentId));
    const invalidRow = changedRows.find((row) => {
      const draft = drafts[row.studentId];
      return !draft || !isValidScoreInput(draft.attendanceScore)
        || !isValidScoreInput(draft.midtermScore)
        || !isValidScoreInput(draft.finalScore);
    });
    if (invalidRow) {
      setSaveError(`Sinh viên ${invalidRow.studentCode} cần đủ ba đầu điểm từ 0 đến 10.`);
      return;
    }

    setSaving(true);
    setSaveError(null);
    try {
      const result = await adminRequest<BatchScoreResult>(
        `/api/admin/subjects/${query.subjectId}/scores/batch`,
        {
          method: 'POST',
          body: JSON.stringify({
            semester: Number(query.semester),
            academicYear: query.academicYear,
            scores: changedRows.map((row) => ({
              studentId: row.studentId,
              attendanceScore: Number(drafts[row.studentId].attendanceScore),
              midtermScore: Number(drafts[row.studentId].midtermScore),
              finalScore: Number(drafts[row.studentId].finalScore),
            })),
          }),
        },
      );
      onNotify(`Đã lưu ${result.scores.length} sinh viên: thêm mới ${result.created}, cập nhật ${result.updated}.`);
      setLoading(true);
      setError(null);
      setReloadKey((current) => current + 1);
    } catch (caught) {
      const message = handleError(caught, 'Không thể lưu bảng điểm.');
      if (message) setSaveError(message);
    } finally {
      setSaving(false);
    }
  };

  const changePage = (nextPage: number) => {
    if (dirtyIds.size > 0 && !window.confirm('Điểm chưa lưu trên trang này sẽ bị bỏ. Bạn vẫn muốn chuyển trang?')) {
      return;
    }
    setLoading(true);
    setError(null);
    setSaveError(null);
    setPage(nextPage);
  };

  return (
    <>
      <section className="score-student-picker subject-score-intro">
        <div className="picker-title">
          <span><BookOpenCheck aria-hidden="true" size={20} /></span>
          <div>
            <strong>Nhập điểm theo môn học</strong>
            <small>Chọn môn và lớp để nhập CC, GK, CK cho cả danh sách sinh viên.</small>
          </div>
        </div>
        <div className="subject-score-hint">
          <UsersRound aria-hidden="true" size={18} />
          <span>Mỗi sinh viên chỉ có một kết quả cho mỗi môn. Lưu lại sẽ cập nhật kết quả đã có.</span>
        </div>
      </section>

      <section className="admin-data-panel subject-score-panel">
        <form className="admin-filters subject-score-filters" onSubmit={loadSheet}>
          <label>
            <span>Môn học *</span>
            <select disabled={optionsLoading || saving} required value={controls.subjectId} onChange={(event) => setControls((current) => ({ ...current, subjectId: event.target.value }))}>
              <option value="">Chọn môn học</option>
              {subjects.map((subject) => <option key={subject.id} value={subject.id}>{subject.subjectCode} · {subject.subjectName}</option>)}
            </select>
          </label>
          <label>
            <span>Lớp *</span>
            <select disabled={classesLoading || saving} required value={controls.classCode} onChange={(event) => setControls((current) => ({ ...current, classCode: event.target.value }))}>
              <option value="">Chọn lớp</option>
              {classes.map((studentClass) => <option key={studentClass.id} value={studentClass.classCode}>{studentClass.classCode} · {studentClass.className}</option>)}
            </select>
          </label>
          <label>
            <span>Học kỳ *</span>
            <select disabled={saving} required value={controls.semester} onChange={(event) => setControls((current) => ({ ...current, semester: event.target.value }))}>
              <option value="1">Học kỳ 1</option>
              <option value="2">Học kỳ 2</option>
            </select>
          </label>
          <label>
            <span>Năm học *</span>
            <select disabled={saving} required value={controls.academicYear} onChange={(event) => setControls((current) => ({ ...current, academicYear: event.target.value }))}>
              {ACADEMIC_YEARS.map((year) => <option key={year} value={year}>{year}</option>)}
            </select>
          </label>
          <label className="subject-score-search">
            <span>Tìm trong lớp</span>
            <div className="admin-input-icon">
              <Search aria-hidden="true" size={16} />
              <input disabled={saving} placeholder="Mã hoặc tên sinh viên" value={controls.keyword} onChange={(event) => setControls((current) => ({ ...current, keyword: event.target.value }))} />
            </div>
          </label>
          <div className="admin-filter-actions">
            <button className="admin-secondary-button" disabled={loading || saving || optionsLoading || classesLoading} type="submit">
              Tải danh sách
            </button>
          </div>
        </form>

        {query && !error && (
          <div className="subject-score-context">
            <div><span>Môn học</span><strong>{selectedSubject?.subjectCode} · {selectedSubject?.subjectName}</strong></div>
            <div><span>Lớp</span><strong>{selectedClass?.classCode} · {selectedClass?.className}</strong></div>
            <div><span>Kỳ áp dụng</span><strong>HK {query.semester} · {query.academicYear}</strong></div>
          </div>
        )}

        {error ? (
          <PanelError message={error} onRetry={() => {
            if (!query) {
              setError(null);
              return;
            }
            setLoading(true);
            setError(null);
            setReloadKey((current) => current + 1);
          }} />
        ) : !query ? (
          <EmptyState title="Chọn môn học và lớp" description="Danh sách sinh viên sẽ hiện ở đây để bạn nhập điểm trực tiếp theo hàng." />
        ) : (
          <>
            <div className="admin-table-wrap" aria-busy={loading}>
              <table className="admin-table subject-score-table">
                <thead><tr><th>Sinh viên</th><th>CC</th><th>GK</th><th>CK</th><th>Tổng</th><th>Chữ</th><th>Trạng thái</th></tr></thead>
                <tbody>
                  {loading ? <TableSkeleton columns={7} /> : sheet.content.length ? sheet.content.map((row) => {
                    const draft = drafts[row.studentId] ?? toDraft(row);
                    const preview = calculateScoreResult(draft.attendanceScore, draft.midtermScore, draft.finalScore);
                    const dirty = dirtyIds.has(row.studentId);
                    return (
                      <tr className={dirty ? 'subject-score-row-dirty' : undefined} key={row.studentId}>
                        <td>
                          <strong className="admin-cell-main">{row.lastName} {row.firstName}</strong>
                          <small>{row.studentCode}</small>
                        </td>
                        <td><input aria-label={`Điểm chuyên cần ${row.studentCode}`} disabled={saving} max={10} min={0} onChange={(event) => updateDraft(row.studentId, 'attendanceScore', event.target.value)} step="0.01" type="number" value={draft.attendanceScore} /></td>
                        <td><input aria-label={`Điểm giữa kỳ ${row.studentCode}`} disabled={saving} max={10} min={0} onChange={(event) => updateDraft(row.studentId, 'midtermScore', event.target.value)} step="0.01" type="number" value={draft.midtermScore} /></td>
                        <td><input aria-label={`Điểm cuối kỳ ${row.studentCode}`} disabled={saving} max={10} min={0} onChange={(event) => updateDraft(row.studentId, 'finalScore', event.target.value)} step="0.01" type="number" value={draft.finalScore} /></td>
                        <td className={`score-number score-total ${preview?.grade === 'F' ? 'score-failed-text' : ''}`}>{preview ? formatScore(preview.totalScore) : '—'}</td>
                        <td><span className={`grade-badge ${scoreGradeTone(preview?.grade ?? null)}`}>{preview?.grade ?? '—'}</span></td>
                        <td><span className={`subject-score-state ${dirty ? 'state-unsaved' : row.scoreId ? 'state-saved' : 'state-empty'}`}>{dirty ? 'Chưa lưu' : row.scoreId ? `Đã lưu · HK ${row.semester}` : 'Chưa có điểm'}</span></td>
                      </tr>
                    );
                  }) : <tr><td colSpan={7}><EmptyState title="Lớp chưa có sinh viên phù hợp" description="Kiểm tra lớp đã chọn hoặc từ khóa tìm kiếm." /></td></tr>}
                </tbody>
              </table>
            </div>

            <div className="subject-score-savebar">
              <div>
                <strong>{dirtyIds.size ? `${dirtyIds.size} sinh viên có thay đổi` : 'Không có thay đổi chưa lưu'}</strong>
                <span>Tổng kết làm tròn một chữ số; điểm chữ được backend tự tính.</span>
              </div>
              <button className="admin-primary-button" disabled={saving || loading || dirtyIds.size === 0} onClick={saveScores} type="button">
                <Save aria-hidden="true" size={17} /> {saving ? 'Đang lưu…' : 'Lưu bảng điểm'}
              </button>
            </div>
            <div className="subject-score-form-alert"><FormAlert message={saveError} /></div>
            {!loading && <Pagination {...sheet} onPageChange={changePage} />}
          </>
        )}
      </section>
    </>
  );
}
