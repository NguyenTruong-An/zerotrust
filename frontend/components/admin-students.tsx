'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { Eye, Pencil, Plus, Search, UserPlus } from 'lucide-react';
import { AuthenticationExpiredError } from '../lib/api';
import {
  adminRequest,
  emptyPage,
  PageResponse,
  queryPath,
  Student,
  StudentClass,
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

type StudentFilters = {
  keyword: string;
  classCode: string;
  status: string;
  sort: string;
};

const INITIAL_FILTERS: StudentFilters = {
  keyword: '',
  classCode: '',
  status: '',
  sort: 'studentCode,asc',
};

type StudentsPanelProps = {
  onAuthenticationExpired: () => void;
  onChanged: () => void;
  onNotify: (message: string) => void;
  onOpenScores: (student: Student) => void;
};

function fullName(student: Pick<Student, 'firstName' | 'lastName'>): string {
  return `${student.lastName} ${student.firstName}`.trim();
}

function optionalText(value: FormDataEntryValue | null): string | null {
  const normalized = String(value ?? '').trim();
  return normalized || null;
}

export function StudentsPanel({
  onAuthenticationExpired,
  onChanged,
  onNotify,
  onOpenScores,
}: StudentsPanelProps) {
  const [draftFilters, setDraftFilters] = useState<StudentFilters>(INITIAL_FILTERS);
  const [filters, setFilters] = useState<StudentFilters>(INITIAL_FILTERS);
  const [students, setStudents] = useState<PageResponse<Student>>(emptyPage());
  const [classes, setClasses] = useState<StudentClass[]>([]);
  const [page, setPage] = useState(0);
  const [reloadKey, setReloadKey] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [detailStudentId, setDetailStudentId] = useState<string | null>(null);
  const [selectedStudent, setSelectedStudent] = useState<Student | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [updateBusy, setUpdateBusy] = useState(false);

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
      .then((result) => active && setClasses(result.content))
      .catch((caught) => {
        if (caught instanceof AuthenticationExpiredError) onAuthenticationExpired();
      });
    return () => { active = false; };
  }, [onAuthenticationExpired, reloadKey]);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();

    adminRequest<PageResponse<Student>>(
      queryPath('/api/admin/students', {
        keyword: filters.keyword,
        classCode: filters.classCode,
        status: filters.status,
        sort: filters.sort,
        page,
        size: 10,
      }),
      { signal: controller.signal },
    )
      .then((result) => active && setStudents(result))
      .catch((caught) => {
        if (!active || controller.signal.aborted) return;
        const message = handleError(caught, 'Không thể tải danh sách sinh viên.');
        if (message) setError(message);
      })
      .finally(() => active && setLoading(false));

    return () => {
      active = false;
      controller.abort();
    };
  }, [filters, handleError, page, reloadKey]);

  const submitFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setPage(0);
    setFilters({ ...draftFilters, keyword: draftFilters.keyword.trim() });
  };

  const clearFilters = () => {
    setLoading(true);
    setError(null);
    setDraftFilters(INITIAL_FILTERS);
    setFilters({ ...INITIAL_FILTERS });
    setPage(0);
  };

  const createStudent = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    setCreateBusy(true);
    setCreateError(null);
    try {
      await adminRequest<Student>('/api/admin/students', {
        method: 'POST',
        body: JSON.stringify({
          username: String(values.get('username') ?? '').trim(),
          password: String(values.get('password') ?? ''),
          email: String(values.get('email') ?? '').trim(),
          firstName: String(values.get('firstName') ?? '').trim(),
          lastName: String(values.get('lastName') ?? '').trim(),
          studentCode: String(values.get('studentCode') ?? '').trim(),
          dateOfBirth: String(values.get('dateOfBirth') ?? ''),
          gender: String(values.get('gender') ?? ''),
          phone: optionalText(values.get('phone')),
          address: optionalText(values.get('address')),
          classCode: String(values.get('classCode') ?? '').trim(),
        }),
      });
      form.reset();
      setCreateOpen(false);
      setLoading(true);
      setError(null);
      setReloadKey((value) => value + 1);
      onChanged();
      onNotify('Tạo tài khoản và hồ sơ sinh viên thành công.');
    } catch (caught) {
      const message = handleError(caught, 'Không thể tạo sinh viên.');
      if (message) setCreateError(message);
    } finally {
      setCreateBusy(false);
    }
  };

  const openDetails = async (studentId: string) => {
    setDetailStudentId(studentId);
    setSelectedStudent(null);
    setDetailLoading(true);
    setDetailError(null);
    try {
      const result = await adminRequest<Student>(`/api/admin/students/${studentId}`);
      setSelectedStudent(result);
    } catch (caught) {
      const message = handleError(caught, 'Không thể tải hồ sơ sinh viên.');
      if (message) setDetailError(message);
    } finally {
      setDetailLoading(false);
    }
  };

  const updateStudent = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedStudent) return;
    const values = new FormData(event.currentTarget);
    setUpdateBusy(true);
    setDetailError(null);
    try {
      const updated = await adminRequest<Student>(`/api/admin/students/${selectedStudent.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          email: String(values.get('email') ?? '').trim(),
          firstName: String(values.get('firstName') ?? '').trim(),
          lastName: String(values.get('lastName') ?? '').trim(),
          studentCode: String(values.get('studentCode') ?? '').trim(),
          dateOfBirth: String(values.get('dateOfBirth') ?? ''),
          gender: String(values.get('gender') ?? ''),
          phone: optionalText(values.get('phone')) ?? '',
          address: optionalText(values.get('address')) ?? '',
          classCode: String(values.get('classCode') ?? '').trim(),
        }),
      });
      setSelectedStudent(updated);
      setLoading(true);
      setError(null);
      setReloadKey((value) => value + 1);
      onChanged();
      onNotify('Cập nhật hồ sơ sinh viên thành công.');
    } catch (caught) {
      const message = handleError(caught, 'Không thể cập nhật sinh viên.');
      if (message) setDetailError(message);
    } finally {
      setUpdateBusy(false);
    }
  };

  const closeDetails = () => {
    setDetailStudentId(null);
    setSelectedStudent(null);
    setDetailError(null);
  };

  const detailsOpen = detailStudentId !== null;

  return (
    <>
      <section className="admin-page-heading">
        <div>
          <p className="eyebrow">Hồ sơ và tài khoản</p>
          <h1>Quản lý sinh viên</h1>
          <p>Tạo tài khoản Keycloak, tra cứu và cập nhật thông tin học vụ.</p>
        </div>
        <button className="admin-primary-button" onClick={() => setCreateOpen(true)} type="button">
          <UserPlus aria-hidden="true" size={17} /> Thêm sinh viên
        </button>
      </section>

      <section className="admin-data-panel">
        <form className="admin-filters admin-filters-four" onSubmit={submitFilters}>
          <label>
            <span>Tìm kiếm</span>
            <div className="admin-input-icon">
              <Search aria-hidden="true" size={16} />
              <input
                placeholder="Mã, tên, email, username"
                value={draftFilters.keyword}
                onChange={(event) => setDraftFilters((current) => ({ ...current, keyword: event.target.value }))}
              />
            </div>
          </label>
          <label>
            <span>Lớp</span>
            <select
              value={draftFilters.classCode}
              onChange={(event) => setDraftFilters((current) => ({ ...current, classCode: event.target.value }))}
            >
              <option value="">Tất cả lớp</option>
              {classes.map((studentClass) => (
                <option key={studentClass.id} value={studentClass.classCode}>
                  {studentClass.classCode} · {studentClass.className}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>Trạng thái</span>
            <select
              value={draftFilters.status}
              onChange={(event) => setDraftFilters((current) => ({ ...current, status: event.target.value }))}
            >
              <option value="">Tất cả</option>
              <option value="ACTIVE">Đang hoạt động</option>
              <option value="INACTIVE">Ngừng hoạt động</option>
              <option value="DELETED">Đã xóa</option>
            </select>
          </label>
          <label>
            <span>Sắp xếp</span>
            <select
              value={draftFilters.sort}
              onChange={(event) => setDraftFilters((current) => ({ ...current, sort: event.target.value }))}
            >
              <option value="studentCode,asc">Mã sinh viên A–Z</option>
              <option value="studentCode,desc">Mã sinh viên Z–A</option>
              <option value="username,asc">Username A–Z</option>
              <option value="classCode,asc">Lớp A–Z</option>
              <option value="createdAt,desc">Tạo gần nhất</option>
            </select>
          </label>
          <div className="admin-filter-actions">
            <button className="admin-secondary-button" disabled={loading} type="submit">Lọc dữ liệu</button>
            <button className="admin-text-button" disabled={loading} onClick={clearFilters} type="button">Đặt lại</button>
          </div>
        </form>

        {error ? (
          <PanelError message={error} onRetry={() => {
            setLoading(true);
            setError(null);
            setReloadKey((value) => value + 1);
          }} />
        ) : (
          <div className="admin-table-wrap" aria-busy={loading}>
            <table className="admin-table admin-student-table">
              <thead>
                <tr>
                  <th>Sinh viên</th>
                  <th>Tài khoản</th>
                  <th>Lớp</th>
                  <th>Trạng thái</th>
                  <th aria-label="Thao tác" />
                </tr>
              </thead>
              <tbody>
                {loading ? <TableSkeleton columns={5} /> : students.content.length ? (
                  students.content.map((student) => (
                    <tr key={student.id}>
                      <td>
                        <div className="admin-person-cell">
                          <span>{student.firstName.charAt(0)}{student.lastName.charAt(0)}</span>
                          <div>
                            <strong>{fullName(student)}</strong>
                            <small>{student.studentCode}</small>
                          </div>
                        </div>
                      </td>
                      <td><strong className="admin-cell-main">{student.username}</strong><small>{student.email}</small></td>
                      <td><strong className="admin-cell-main">{student.classCode}</strong><small>{student.className}</small></td>
                      <td><StatusBadge status={student.status} /></td>
                      <td>
                        <div className="admin-row-actions">
                          <button title="Xem và sửa" onClick={() => void openDetails(student.id)} type="button">
                            <Pencil aria-hidden="true" size={15} />
                          </button>
                          <button title="Xem bảng điểm" onClick={() => onOpenScores(student)} type="button">
                            <Eye aria-hidden="true" size={15} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr><td colSpan={5}><EmptyState title="Chưa có sinh viên phù hợp" description="Thử thay đổi bộ lọc hoặc tạo hồ sơ mới." /></td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
        {!error && !loading && (
          <Pagination {...students} onPageChange={(nextPage) => {
            setLoading(true);
            setError(null);
            setPage(nextPage);
          }} />
        )}
      </section>

      {createOpen && (
        <Modal
          eyebrow="Tạo tài khoản Keycloak"
          title="Thêm sinh viên"
          description="Admin đặt mật khẩu ban đầu; hệ thống không yêu cầu đổi mật khẩu lần đăng nhập đầu."
          onClose={() => !createBusy && setCreateOpen(false)}
          wide
        >
          <form className="admin-form" onSubmit={createStudent}>
            <FormAlert message={createError} />
            <div className="admin-form-section">
              <h3>Thông tin tài khoản</h3>
              <div className="admin-form-grid">
                <label><span>Username *</span><input autoComplete="off" maxLength={50} minLength={4} name="username" pattern="[A-Za-z0-9._-]+" required /></label>
                <label><span>Mật khẩu *</span><input autoComplete="new-password" maxLength={100} minLength={8} name="password" required type="password" /></label>
                <label className="admin-field-wide"><span>Email *</span><input maxLength={254} name="email" required type="email" /></label>
              </div>
            </div>
            <div className="admin-form-section">
              <h3>Hồ sơ sinh viên</h3>
              <div className="admin-form-grid">
                <label><span>Họ *</span><input maxLength={100} name="lastName" required /></label>
                <label><span>Tên *</span><input maxLength={100} name="firstName" required /></label>
                <label><span>Mã sinh viên *</span><input maxLength={30} name="studentCode" required /></label>
                <label><span>Ngày sinh *</span><input max={new Date().toISOString().slice(0, 10)} name="dateOfBirth" required type="date" /></label>
                <label>
                  <span>Giới tính *</span>
                  <select defaultValue="" name="gender" required>
                    <option disabled value="">Chọn giới tính</option>
                    <option value="MALE">Nam</option><option value="FEMALE">Nữ</option><option value="OTHER">Khác</option>
                  </select>
                </label>
                <label>
                  <span>Lớp *</span>
                  <select defaultValue="" name="classCode" required>
                    <option disabled value="">Chọn lớp</option>
                    {classes.map((studentClass) => <option key={studentClass.id} value={studentClass.classCode}>{studentClass.classCode} · {studentClass.className}</option>)}
                  </select>
                </label>
                <label><span>Số điện thoại</span><input maxLength={20} name="phone" pattern="[0-9+(). \-]*" /></label>
                <label className="admin-field-wide"><span>Địa chỉ</span><textarea maxLength={500} name="address" rows={2} /></label>
              </div>
            </div>
            <div className="admin-form-footer">
              <button className="admin-text-button" disabled={createBusy} onClick={() => setCreateOpen(false)} type="button">Hủy</button>
              <SubmitButton busy={createBusy}><Plus aria-hidden="true" size={17} /> Tạo sinh viên</SubmitButton>
            </div>
          </form>
        </Modal>
      )}

      {detailsOpen && (
        <Modal
          eyebrow="GET & PATCH /students/{id}"
          title={selectedStudent ? fullName(selectedStudent) : 'Chi tiết sinh viên'}
          description={selectedStudent ? `${selectedStudent.studentCode} · @${selectedStudent.username}` : undefined}
          onClose={() => {
            if (!updateBusy) {
              closeDetails();
            }
          }}
          wide
        >
          {detailLoading ? (
            <div className="admin-modal-loading"><span className="auth-spinner" /><p>Đang tải hồ sơ…</p></div>
          ) : selectedStudent ? (
            <form className="admin-form" key={selectedStudent.id} onSubmit={updateStudent}>
              <FormAlert message={detailError} />
              <div className="admin-detail-strip">
                <div><span>Username</span><strong>{selectedStudent.username}</strong></div>
                <div><span>Trạng thái</span><StatusBadge status={selectedStudent.status} /></div>
                <button className="admin-secondary-button" onClick={() => onOpenScores(selectedStudent)} type="button">
                  Xem bảng điểm
                </button>
              </div>
              <div className="admin-form-grid">
                <label><span>Họ *</span><input defaultValue={selectedStudent.lastName} maxLength={100} name="lastName" required /></label>
                <label><span>Tên *</span><input defaultValue={selectedStudent.firstName} maxLength={100} name="firstName" required /></label>
                <label><span>Email *</span><input defaultValue={selectedStudent.email} maxLength={254} name="email" required type="email" /></label>
                <label><span>Mã sinh viên *</span><input defaultValue={selectedStudent.studentCode} maxLength={30} name="studentCode" required /></label>
                <label><span>Ngày sinh *</span><input defaultValue={selectedStudent.dateOfBirth} max={new Date().toISOString().slice(0, 10)} name="dateOfBirth" required type="date" /></label>
                <label>
                  <span>Giới tính *</span>
                  <select defaultValue={selectedStudent.gender} name="gender" required>
                    <option value="MALE">Nam</option><option value="FEMALE">Nữ</option><option value="OTHER">Khác</option>
                  </select>
                </label>
                <label>
                  <span>Lớp *</span>
                  <select defaultValue={selectedStudent.classCode} name="classCode" required>
                    {classes.map((studentClass) => <option key={studentClass.id} value={studentClass.classCode}>{studentClass.classCode} · {studentClass.className}</option>)}
                  </select>
                </label>
                <label><span>Số điện thoại</span><input defaultValue={selectedStudent.phone ?? ''} maxLength={20} name="phone" pattern="[0-9+(). \-]*" /></label>
                <label className="admin-field-wide"><span>Địa chỉ</span><textarea defaultValue={selectedStudent.address ?? ''} maxLength={500} name="address" rows={3} /></label>
              </div>
              <div className="admin-form-footer">
                <button className="admin-text-button" disabled={updateBusy} onClick={closeDetails} type="button">Đóng</button>
                <SubmitButton busy={updateBusy}><Pencil aria-hidden="true" size={16} /> Lưu thay đổi</SubmitButton>
              </div>
            </form>
          ) : (
            <PanelError
              message={detailError ?? 'Không thể tải hồ sơ.'}
              onRetry={() => {
                if (detailStudentId) void openDetails(detailStudentId);
              }}
            />
          )}
        </Modal>
      )}
    </>
  );
}
