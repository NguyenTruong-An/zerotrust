'use client';

import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import { BookOpen, Plus, School, Search, Trash2, UserCog } from 'lucide-react';
import { AuthenticationExpiredError } from '../lib/api';
import {
  adminRequest,
  emptyPage,
  PageResponse,
  queryPath,
  StudentClass,
  Subject,
  UserAccount,
} from '../lib/admin-api';
import {
  EmptyState,
  FormAlert,
  Modal,
  Pagination,
  PanelError,
  StatusBadge,
  SubmitButton,
  TableSkeleton,
} from './admin-ui';

type SharedProps = {
  onAuthenticationExpired: () => void;
  onChanged: () => void;
  onNotify: (message: string) => void;
};

const DEPARTMENTS = [
  'An toàn thông tin',
  'Công nghệ thông tin',
  'Điện tử viễn thông',
] as const;

function useErrorHandler(onAuthenticationExpired: () => void) {
  return useCallback((caught: unknown, fallback: string): string | null => {
    if (caught instanceof AuthenticationExpiredError) {
      onAuthenticationExpired();
      return null;
    }
    return caught instanceof Error ? caught.message : fallback;
  }, [onAuthenticationExpired]);
}

export function ClassesPanel({ onAuthenticationExpired, onChanged, onNotify }: SharedProps) {
  const [draft, setDraft] = useState({ keyword: '', department: '', courseYears: '', sort: 'classCode,asc' });
  const [filters, setFilters] = useState(draft);
  const [classes, setClasses] = useState<PageResponse<StudentClass>>(emptyPage());
  const [page, setPage] = useState(0);
  const [reloadKey, setReloadKey] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [deletingClass, setDeletingClass] = useState<StudentClass | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const handleError = useErrorHandler(onAuthenticationExpired);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    adminRequest<PageResponse<StudentClass>>(queryPath('/api/admin/student-classes', {
      ...filters,
      page,
      size: 10,
    }), { signal: controller.signal })
      .then((result) => active && setClasses(result))
      .catch((caught) => {
        if (!active || controller.signal.aborted) return;
        const message = handleError(caught, 'Không thể tải danh sách lớp.');
        if (message) setError(message);
      })
      .finally(() => active && setLoading(false));
    return () => { active = false; controller.abort(); };
  }, [filters, handleError, page, reloadKey]);

  const submitFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setPage(0);
    setFilters({
      ...draft,
      keyword: draft.keyword.trim(),
      department: draft.department.trim(),
      courseYears: draft.courseYears.trim(),
    });
  };

  const resetFilters = () => {
    const initial = { keyword: '', department: '', courseYears: '', sort: 'classCode,asc' };
    setLoading(true); setError(null);
    setDraft(initial); setFilters(initial); setPage(0);
  };

  const createClass = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    setCreateBusy(true); setCreateError(null);
    try {
      await adminRequest<StudentClass>('/api/admin/student-classes', {
        method: 'POST',
        body: JSON.stringify({
          classCode: String(values.get('classCode') ?? '').trim(),
          className: String(values.get('className') ?? '').trim(),
          department: String(values.get('department') ?? '').trim(),
          courseYears: String(values.get('courseYears') ?? '').trim(),
        }),
      });
      form.reset(); setCreateOpen(false); setLoading(true); setError(null); setReloadKey((value) => value + 1);
      onChanged(); onNotify('Tạo lớp thành công.');
    } catch (caught) {
      const message = handleError(caught, 'Không thể tạo lớp.');
      if (message) setCreateError(message);
    } finally { setCreateBusy(false); }
  };

  const deleteClass = async () => {
    if (!deletingClass) return;
    setDeleteBusy(true); setDeleteError(null);
    try {
      await adminRequest<void>(`/api/admin/student-classes/${deletingClass.id}`, {
        method: 'DELETE',
      });
      const deletedClassCode = deletingClass.classCode;
      setDeletingClass(null); setLoading(true); setError(null);
      if (classes.content.length === 1 && page > 0) setPage((current) => current - 1);
      setReloadKey((value) => value + 1);
      onChanged(); onNotify(`Đã xóa lớp ${deletedClassCode}.`);
    } catch (caught) {
      const message = handleError(caught, 'Không thể xóa lớp.');
      if (message) setDeleteError(message);
    } finally { setDeleteBusy(false); }
  };

  return (
    <>
      <section className="admin-page-heading">
        <div><p className="eyebrow">Danh mục đào tạo</p><h1>Lớp</h1><p>Quản lý lớp theo khoa và khóa học.</p></div>
        <button className="admin-primary-button" onClick={() => setCreateOpen(true)} type="button"><Plus aria-hidden="true" size={17} /> Tạo lớp</button>
      </section>
      <section className="admin-data-panel">
        <form className="admin-filters admin-filters-four" onSubmit={submitFilters}>
          <label><span>Tìm kiếm</span><div className="admin-input-icon"><Search aria-hidden="true" size={16} /><input placeholder="Mã hoặc tên lớp" value={draft.keyword} onChange={(event) => setDraft((current) => ({ ...current, keyword: event.target.value }))} /></div></label>
          <label><span>Khoa</span><select value={draft.department} onChange={(event) => setDraft((current) => ({ ...current, department: event.target.value }))}><option value="">Tất cả khoa</option>{DEPARTMENTS.map((department) => <option key={department} value={department}>{department}</option>)}</select></label>
          <label><span>Khóa học</span><input placeholder="2022-2027" pattern="[0-9]{4}-[0-9]{4}" value={draft.courseYears} onChange={(event) => setDraft((current) => ({ ...current, courseYears: event.target.value }))} /></label>
          <label><span>Sắp xếp</span><select value={draft.sort} onChange={(event) => setDraft((current) => ({ ...current, sort: event.target.value }))}><option value="classCode,asc">Mã lớp A–Z</option><option value="className,asc">Tên lớp A–Z</option><option value="department,asc">Khoa A–Z</option><option value="courseYears,desc">Khóa học mới nhất</option></select></label>
          <div className="admin-filter-actions"><button className="admin-secondary-button" disabled={loading} type="submit">Lọc dữ liệu</button><button className="admin-text-button" disabled={loading} onClick={resetFilters} type="button">Đặt lại</button></div>
        </form>
        {error ? <PanelError message={error} onRetry={() => { setLoading(true); setError(null); setReloadKey((value) => value + 1); }} /> : (
          <div className="admin-table-wrap" aria-busy={loading}>
            <table className="admin-table"><thead><tr><th>Mã lớp</th><th>Tên lớp</th><th>Khoa</th><th>Khóa học</th><th aria-label="Thao tác" /></tr></thead>
              <tbody>{loading ? <TableSkeleton columns={5} /> : classes.content.length ? classes.content.map((item) => <tr key={item.id}><td><span className="admin-code-badge">{item.classCode}</span></td><td><strong className="admin-cell-main">{item.className}</strong></td><td>{item.department}</td><td>{item.courseYears}</td><td><div className="admin-row-actions"><button aria-label={`Xóa lớp ${item.classCode}`} className="admin-danger-icon" onClick={() => { setDeletingClass(item); setDeleteError(null); }} title="Xóa lớp" type="button"><Trash2 aria-hidden="true" size={15} /></button></div></td></tr>) : <tr><td colSpan={5}><EmptyState title="Chưa có lớp phù hợp" description="Thử thay đổi bộ lọc hoặc tạo lớp mới." /></td></tr>}</tbody>
            </table>
          </div>
        )}
        {!error && !loading && <Pagination {...classes} onPageChange={(nextPage) => { setLoading(true); setError(null); setPage(nextPage); }} />}
      </section>
      {createOpen && <Modal eyebrow="POST /student-classes" title="Tạo lớp" description="Mã lớp sẽ được chuẩn hóa thành chữ in hoa." onClose={() => { if (!createBusy) setCreateOpen(false); }}>
        <form className="admin-form" onSubmit={createClass}><FormAlert message={createError} /><div className="admin-form-grid">
          <label><span>Mã lớp *</span><input maxLength={30} name="classCode" pattern="[A-Za-z0-9_-]+" required /></label>
          <label><span>Tên lớp *</span><input maxLength={100} name="className" required /></label>
          <label className="admin-field-wide"><span>Khoa *</span><select defaultValue="" name="department" required><option disabled value="">Chọn khoa</option>{DEPARTMENTS.map((department) => <option key={department} value={department}>{department}</option>)}</select></label>
          <label><span>Khóa học *</span><input maxLength={9} name="courseYears" pattern="[0-9]{4}-[0-9]{4}" placeholder="2022-2027" required /></label>
        </div><div className="admin-form-footer"><button className="admin-text-button" disabled={createBusy} onClick={() => setCreateOpen(false)} type="button">Hủy</button><SubmitButton busy={createBusy}><School aria-hidden="true" size={17} /> Tạo lớp</SubmitButton></div></form>
      </Modal>}
      {deletingClass && <Modal eyebrow={`${deletingClass.classCode} · ${deletingClass.courseYears}`} title="Xóa lớp?" description="Chỉ có thể xóa lớp chưa có sinh viên." onClose={() => { if (!deleteBusy) setDeletingClass(null); }}>
        <div className="admin-delete-confirmation"><FormAlert message={deleteError} /><p>Bạn đang xóa lớp <strong>{deletingClass.className}</strong>. Thao tác này không thể hoàn tác.</p><div className="admin-form-footer"><button className="admin-text-button" disabled={deleteBusy} onClick={() => setDeletingClass(null)} type="button">Hủy</button><button className="admin-primary-button admin-danger-button" disabled={deleteBusy} onClick={() => void deleteClass()} type="button"><Trash2 aria-hidden="true" size={16} /> {deleteBusy ? 'Đang xóa…' : 'Xóa lớp'}</button></div></div>
      </Modal>}
    </>
  );
}

export function SubjectsPanel({ onAuthenticationExpired, onChanged, onNotify }: SharedProps) {
  const [draft, setDraft] = useState({ keyword: '', sort: 'subjectCode,asc' });
  const [filters, setFilters] = useState(draft);
  const [subjects, setSubjects] = useState<PageResponse<Subject>>(emptyPage());
  const [page, setPage] = useState(0);
  const [reloadKey, setReloadKey] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [deletingSubject, setDeletingSubject] = useState<Subject | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const handleError = useErrorHandler(onAuthenticationExpired);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    adminRequest<PageResponse<Subject>>(queryPath('/api/admin/subjects', { ...filters, page, size: 10 }), { signal: controller.signal })
      .then((result) => active && setSubjects(result))
      .catch((caught) => {
        if (!active || controller.signal.aborted) return;
        const message = handleError(caught, 'Không thể tải danh sách môn học.');
        if (message) setError(message);
      })
      .finally(() => active && setLoading(false));
    return () => { active = false; controller.abort(); };
  }, [filters, handleError, page, reloadKey]);

  const createSubject = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); const form = event.currentTarget; const values = new FormData(form);
    setCreateBusy(true); setCreateError(null);
    try {
      await adminRequest<Subject>('/api/admin/subjects', { method: 'POST', body: JSON.stringify({
        subjectCode: String(values.get('subjectCode') ?? '').trim(),
        subjectName: String(values.get('subjectName') ?? '').trim(),
        credits: Number(values.get('credits')),
        description: String(values.get('description') ?? '').trim() || null,
      }) });
      form.reset(); setCreateOpen(false); setLoading(true); setError(null); setReloadKey((value) => value + 1);
      onChanged(); onNotify('Tạo môn học thành công.');
    } catch (caught) {
      const message = handleError(caught, 'Không thể tạo môn học.');
      if (message) setCreateError(message);
    } finally { setCreateBusy(false); }
  };

  const deleteSubject = async () => {
    if (!deletingSubject) return;
    setDeleteBusy(true); setDeleteError(null);
    try {
      await adminRequest<void>(`/api/admin/subjects/${deletingSubject.id}`, {
        method: 'DELETE',
      });
      const deletedSubjectCode = deletingSubject.subjectCode;
      setDeletingSubject(null); setLoading(true); setError(null);
      if (subjects.content.length === 1 && page > 0) setPage((current) => current - 1);
      setReloadKey((value) => value + 1);
      onChanged(); onNotify(`Đã xóa môn học ${deletedSubjectCode}.`);
    } catch (caught) {
      const message = handleError(caught, 'Không thể xóa môn học.');
      if (message) setDeleteError(message);
    } finally { setDeleteBusy(false); }
  };

  const submitFilters = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); setLoading(true); setError(null); setPage(0); setFilters({ ...draft, keyword: draft.keyword.trim() }); };
  const resetFilters = () => { const initial = { keyword: '', sort: 'subjectCode,asc' }; setLoading(true); setError(null); setDraft(initial); setFilters(initial); setPage(0); };

  return (
    <>
      <section className="admin-page-heading"><div><p className="eyebrow">Danh mục đào tạo</p><h1>Môn học</h1><p>Quản lý mã môn, số tín chỉ và mô tả học phần.</p></div><button className="admin-primary-button" onClick={() => setCreateOpen(true)} type="button"><Plus aria-hidden="true" size={17} /> Thêm môn học</button></section>
      <section className="admin-data-panel">
        <form className="admin-filters admin-filters-compact" onSubmit={submitFilters}>
          <label><span>Tìm kiếm</span><div className="admin-input-icon"><Search aria-hidden="true" size={16} /><input placeholder="Mã hoặc tên môn" value={draft.keyword} onChange={(event) => setDraft((current) => ({ ...current, keyword: event.target.value }))} /></div></label>
          <label><span>Sắp xếp</span><select value={draft.sort} onChange={(event) => setDraft((current) => ({ ...current, sort: event.target.value }))}><option value="subjectCode,asc">Mã môn A–Z</option><option value="subjectName,asc">Tên môn A–Z</option><option value="credits,desc">Tín chỉ cao nhất</option></select></label>
          <div className="admin-filter-actions"><button className="admin-secondary-button" disabled={loading} type="submit">Lọc dữ liệu</button><button className="admin-text-button" disabled={loading} onClick={resetFilters} type="button">Đặt lại</button></div>
        </form>
        {error ? <PanelError message={error} onRetry={() => { setLoading(true); setError(null); setReloadKey((value) => value + 1); }} /> : <div className="admin-table-wrap" aria-busy={loading}><table className="admin-table"><thead><tr><th>Mã môn</th><th>Tên môn</th><th>Tín chỉ</th><th>Mô tả</th><th aria-label="Thao tác" /></tr></thead><tbody>{loading ? <TableSkeleton columns={5} /> : subjects.content.length ? subjects.content.map((subject) => <tr key={subject.id}><td><span className="admin-code-badge subject-code">{subject.subjectCode}</span></td><td><strong className="admin-cell-main">{subject.subjectName}</strong></td><td><span className="credit-badge">{subject.credits} TC</span></td><td><p className="admin-description-cell">{subject.description || 'Chưa có mô tả'}</p></td><td><div className="admin-row-actions"><button aria-label={`Xóa môn ${subject.subjectCode}`} className="admin-danger-icon" onClick={() => { setDeletingSubject(subject); setDeleteError(null); }} title="Xóa môn học" type="button"><Trash2 aria-hidden="true" size={15} /></button></div></td></tr>) : <tr><td colSpan={5}><EmptyState title="Chưa có môn học phù hợp" description="Thử thay đổi từ khóa hoặc tạo môn học mới." /></td></tr>}</tbody></table></div>}
        {!error && !loading && <Pagination {...subjects} onPageChange={(nextPage) => { setLoading(true); setError(null); setPage(nextPage); }} />}
      </section>
      {createOpen && <Modal eyebrow="POST /subjects" title="Thêm môn học" description="Mã môn được chuẩn hóa thành chữ in hoa; mã môn và tên môn đều phải duy nhất." onClose={() => { if (!createBusy) setCreateOpen(false); }}>
        <form className="admin-form" onSubmit={createSubject}><FormAlert message={createError} /><div className="admin-form-grid">
          <label><span>Mã môn *</span><input maxLength={30} name="subjectCode" pattern="[A-Za-z0-9_-]+" required /></label>
          <label><span>Số tín chỉ *</span><input max={20} min={1} name="credits" required type="number" /></label>
          <label className="admin-field-wide"><span>Tên môn *</span><input maxLength={200} name="subjectName" required /></label>
          <label className="admin-field-wide"><span>Mô tả</span><textarea maxLength={5000} name="description" rows={4} /></label>
        </div><div className="admin-form-footer"><button className="admin-text-button" disabled={createBusy} onClick={() => setCreateOpen(false)} type="button">Hủy</button><SubmitButton busy={createBusy}><BookOpen aria-hidden="true" size={17} /> Tạo môn học</SubmitButton></div></form>
      </Modal>}
      {deletingSubject && <Modal eyebrow={`${deletingSubject.subjectCode} · ${deletingSubject.credits} tín chỉ`} title="Xóa môn học?" description="Chỉ có thể xóa môn chưa được sử dụng trong bất kỳ bảng điểm nào." onClose={() => { if (!deleteBusy) setDeletingSubject(null); }}>
        <div className="admin-delete-confirmation"><FormAlert message={deleteError} /><p>Bạn đang xóa môn <strong>{deletingSubject.subjectName}</strong>. Thao tác này không thể hoàn tác.</p><div className="admin-form-footer"><button className="admin-text-button" disabled={deleteBusy} onClick={() => setDeletingSubject(null)} type="button">Hủy</button><button className="admin-primary-button admin-danger-button" disabled={deleteBusy} onClick={() => void deleteSubject()} type="button"><Trash2 aria-hidden="true" size={16} /> {deleteBusy ? 'Đang xóa…' : 'Xóa môn học'}</button></div></div>
      </Modal>}
    </>
  );
}

export function UsersPanel({ onAuthenticationExpired }: Pick<SharedProps, 'onAuthenticationExpired'>) {
  const [users, setUsers] = useState<UserAccount[]>([]);
  const [keyword, setKeyword] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const handleError = useErrorHandler(onAuthenticationExpired);

  useEffect(() => {
    let active = true;
    adminRequest<UserAccount[]>('/api/admin/users')
      .then((result) => active && setUsers(result))
      .catch((caught) => { if (!active) return; const message = handleError(caught, 'Không thể tải danh sách tài khoản.'); if (message) setError(message); })
      .finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [handleError, reloadKey]);

  const filteredUsers = useMemo(() => {
    const normalized = keyword.trim().toLocaleLowerCase('vi');
    if (!normalized) return users;
    return users.filter((user) => [user.username, user.email, user.firstName, user.lastName]
      .some((value) => value?.toLocaleLowerCase('vi').includes(normalized)));
  }, [keyword, users]);

  return (
    <>
      <section className="admin-page-heading"><div><p className="eyebrow">Dữ liệu nội bộ</p><h1>Tài khoản người dùng</h1><p>Danh sách tài khoản đã đồng bộ với hệ thống học vụ.</p></div><span className="admin-heading-icon"><UserCog aria-hidden="true" size={22} /></span></section>
      <section className="admin-data-panel">
        <div className="admin-client-filter"><div className="admin-input-icon"><Search aria-hidden="true" size={16} /><input aria-label="Tìm tài khoản" placeholder="Tìm username, email hoặc họ tên" value={keyword} onChange={(event) => setKeyword(event.target.value)} /></div><span>{filteredUsers.length}/{users.length} tài khoản</span></div>
        {error ? <PanelError message={error} onRetry={() => { setLoading(true); setError(null); setReloadKey((value) => value + 1); }} /> : <div className="admin-table-wrap" aria-busy={loading}><table className="admin-table"><thead><tr><th>Người dùng</th><th>Username</th><th>Email</th><th>Trạng thái</th></tr></thead><tbody>{loading ? <TableSkeleton columns={4} /> : filteredUsers.length ? filteredUsers.map((user) => <tr key={user.id}><td><div className="admin-person-cell"><span>{user.firstName?.charAt(0)}{user.lastName?.charAt(0)}</span><div><strong>{`${user.lastName ?? ''} ${user.firstName ?? ''}`.trim() || 'Chưa cập nhật'}</strong></div></div></td><td><strong className="admin-cell-main">{user.username}</strong></td><td>{user.email}</td><td><StatusBadge status={user.status} /></td></tr>) : <tr><td colSpan={4}><EmptyState title="Không có tài khoản phù hợp" description="Thử tìm bằng từ khóa khác." /></td></tr>}</tbody></table></div>}
      </section>
    </>
  );
}
