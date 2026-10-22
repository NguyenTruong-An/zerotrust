'use client';

import { useCallback, useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { AuthenticationExpiredError } from '../lib/api';
import { adminRequest } from '../lib/admin-api';
import type { PageResponse, StudentClass, Subject } from '../lib/admin-api';
import type { Teacher, Assignment, Schedule } from '../lib/teaching-api';
import { weekdayName } from '../lib/teaching-api';

const fetchTeachingData = () => Promise.all([adminRequest<Teacher[]>('/api/admin/teachers'), adminRequest<Assignment[]>('/api/admin/teaching-assignments'), adminRequest<Schedule[]>('/api/admin/schedules'), adminRequest<PageResponse<StudentClass>>('/api/admin/student-classes?size=100'), adminRequest<PageResponse<Subject>>('/api/admin/subjects?size=100')]);

export function AdminTeaching({ onAuthenticationExpired }: { onAuthenticationExpired: () => void }) {
  const [teachers, setTeachers] = useState<Teacher[]>([]); const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [schedules, setSchedules] = useState<Schedule[]>([]); const [classes, setClasses] = useState<StudentClass[]>([]); const [subjects, setSubjects] = useState<Subject[]>([]);
  const [editTeacher, setEditTeacher] = useState<Teacher | null>(null); const [editAssignment, setEditAssignment] = useState<Assignment | null>(null); const [editSchedule, setEditSchedule] = useState<Schedule | null>(null);
  const [error, setError] = useState(''); const [notice, setNotice] = useState(''); const [busy, setBusy] = useState(false);
  const fail = useCallback((e: unknown) => { if (e instanceof AuthenticationExpiredError) onAuthenticationExpired(); else setError(e instanceof Error ? e.message : 'Yêu cầu chưa hoàn tất.'); }, [onAuthenticationExpired]);
  const applyData = useCallback(([t, a, s, c, subject]: Awaited<ReturnType<typeof fetchTeachingData>>) => {
    setTeachers(t); setAssignments(a); setSchedules(s); setClasses(c.content); setSubjects(subject.content);
  }, []);
  useEffect(() => {
    let active = true;
    fetchTeachingData().then((data) => { if (active) applyData(data); }).catch((e) => { if (active) fail(e); });
    return () => { active = false; };
  }, [applyData, fail]);
  const execute = async (action: () => Promise<unknown>, message: string) => {
    setBusy(true); setError(''); setNotice('');
    try { await action(); applyData(await fetchTeachingData()); setNotice(message); return true; } catch (e) { fail(e); return false; } finally { setBusy(false); }
  };
  const teacherSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); const form = event.currentTarget; const d = new FormData(form);
    const body: Record<string, string> = Object.fromEntries(['teacherCode', 'email', 'firstName', 'lastName'].map((k) => [k, String(d.get(k))]));
    if (editTeacher) body.status = String(d.get('status')); else { body.username = String(d.get('username')); body.password = String(d.get('password')); }
    const success = await execute(() => adminRequest(editTeacher ? `/api/admin/teachers/${editTeacher.id}` : '/api/admin/teachers', { method: editTeacher ? 'PUT' : 'POST', body: JSON.stringify(body) }), editTeacher ? 'Đã cập nhật giảng viên.' : 'Đã tạo giảng viên và tài khoản Keycloak.');
    if (success) { form.reset(); setEditTeacher(null); }
  };
  const assignmentSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); const form = event.currentTarget; const d = new FormData(form); const body = Object.fromEntries(['teacherId', 'classId', 'subjectId'].map((k) => [k, String(d.get(k))]));
    if (await execute(() => adminRequest(editAssignment ? `/api/admin/teaching-assignments/${editAssignment.id}` : '/api/admin/teaching-assignments', { method: editAssignment ? 'PUT' : 'POST', body: JSON.stringify(body) }), 'Đã lưu phân công.')) { form.reset(); setEditAssignment(null); }
  };
  const scheduleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); const form = event.currentTarget; const d = new FormData(form);
    const body = { assignmentId: String(d.get('assignmentId')), weekday: Number(d.get('weekday')), startTime: String(d.get('startTime')), endTime: String(d.get('endTime')), room: String(d.get('room')) };
    if (await execute(() => adminRequest(editSchedule ? `/api/admin/schedules/${editSchedule.id}` : '/api/admin/schedules', { method: editSchedule ? 'PUT' : 'POST', body: JSON.stringify(body) }), 'Đã lưu lịch học.')) { form.reset(); setEditSchedule(null); }
  };
  return <div className="teaching-admin" data-testid="admin-teaching">
    {error && <p role="alert" className="teaching-error">{error}</p>}{notice && <p role="status" className="teaching-notice">{notice}</p>}
    <section className="teaching-card"><h2>Giảng viên</h2><form key={editTeacher?.id ?? 'new-teacher'} className="teaching-form" onSubmit={(e) => void teacherSubmit(e)}>
      {!editTeacher && <><label>Tên đăng nhập<input name="username" required maxLength={100} autoComplete="off" /></label><label>Mật khẩu ban đầu<input name="password" type="password" required minLength={8} maxLength={128} autoComplete="new-password" /></label></>}
      <label>Mã giảng viên<input name="teacherCode" required maxLength={30} defaultValue={editTeacher?.teacherCode} /></label><label>Họ<input name="firstName" required maxLength={100} defaultValue={editTeacher?.firstName} /></label><label>Tên<input name="lastName" required maxLength={100} defaultValue={editTeacher?.lastName} /></label><label>Email<input name="email" type="email" required maxLength={254} defaultValue={editTeacher?.email} /></label>
      {editTeacher && <label>Trạng thái hồ sơ<select name="status" defaultValue={editTeacher.status}><option value="ACTIVE">Hoạt động</option><option value="INACTIVE">Tạm ngưng quyền học vụ</option></select></label>}
      <button disabled={busy} type="submit">{editTeacher ? 'Lưu giảng viên' : 'Tạo giảng viên'}</button>{editTeacher && <button onClick={() => setEditTeacher(null)} type="button">Hủy sửa</button>}
    </form><div className="teaching-table-wrap"><table><thead><tr><th>Mã</th><th>Họ tên</th><th>Email</th><th>Trạng thái</th><th>Thao tác</th></tr></thead><tbody>{teachers.map((t) => <tr key={t.id}><td>{t.teacherCode}</td><td>{t.firstName} {t.lastName}</td><td>{t.email}</td><td>{t.status}</td><td><button disabled={busy} onClick={() => setEditTeacher(t)} type="button">Sửa {t.teacherCode}</button></td></tr>)}</tbody></table></div><p>Hồ sơ tạm ngưng không được truy cập API giảng viên. Trạng thái đăng nhập Keycloak được quản lý riêng.</p></section>
    <section className="teaching-card"><h2>Phân công lớp và môn</h2><form key={editAssignment?.id ?? 'new-assignment'} className="teaching-form" onSubmit={(e) => void assignmentSubmit(e)}>
      <label>Giảng viên<select name="teacherId" required defaultValue={editAssignment?.teacherId ?? ''}><option value="">Chọn giảng viên</option>{teachers.filter((t) => t.status === 'ACTIVE').map((t) => <option key={t.id} value={t.id}>{t.teacherCode} · {t.firstName} {t.lastName}</option>)}</select></label>
      <label>Lớp<select name="classId" required defaultValue={editAssignment?.classId ?? ''}><option value="">Chọn lớp</option>{classes.map((c) => <option key={c.id} value={c.id}>{c.classCode}</option>)}</select></label><label>Môn học<select name="subjectId" required defaultValue={editAssignment?.subjectId ?? ''}><option value="">Chọn môn</option>{subjects.map((s) => <option key={s.id} value={s.id}>{s.subjectCode} · {s.subjectName}</option>)}</select></label>
      <button disabled={busy} type="submit">Lưu phân công</button>{editAssignment && <button onClick={() => setEditAssignment(null)} type="button">Hủy sửa</button>}
    </form><div className="teaching-table-wrap"><table><thead><tr><th>Giảng viên</th><th>Lớp</th><th>Môn</th><th>Thao tác</th></tr></thead><tbody>{assignments.map((a) => <tr key={a.id}><td>{a.teacherName}</td><td>{a.classCode}</td><td>{a.subjectName}</td><td><button disabled={busy} onClick={() => setEditAssignment(a)} type="button">Sửa phân công</button> <button disabled={busy} onClick={() => void execute(() => adminRequest(`/api/admin/teaching-assignments/${a.id}`, { method: 'DELETE' }), 'Đã xóa phân công không còn lịch.')} type="button">Xóa phân công</button></td></tr>)}</tbody></table></div></section>
    <section className="teaching-card"><h2>Lịch học</h2><form key={editSchedule?.id ?? 'new-schedule'} className="teaching-form" onSubmit={(e) => void scheduleSubmit(e)}>
      <label>Phân công<select name="assignmentId" required defaultValue={editSchedule?.assignmentId ?? ''}>{!editSchedule && <option value="">Chọn phân công</option>}{assignments.filter((a) => !editSchedule || a.id === editSchedule.assignmentId).map((a) => <option key={a.id} value={a.id}>{a.classCode} · {a.subjectName} · {a.teacherName}</option>)}</select></label>
      <label>Ngày<select name="weekday" defaultValue={editSchedule?.weekday ?? 1}>{[1,2,3,4,5,6,7].map((d) => <option key={d} value={d}>{weekdayName(d)}</option>)}</select></label><label>Bắt đầu<input name="startTime" type="time" required defaultValue={editSchedule?.startTime.slice(0,5)} /></label><label>Kết thúc<input name="endTime" type="time" required defaultValue={editSchedule?.endTime.slice(0,5)} /></label><label>Phòng<input name="room" required maxLength={80} defaultValue={editSchedule?.room} /></label>
      <button disabled={busy} type="submit">Lưu lịch học</button>{editSchedule && <button onClick={() => setEditSchedule(null)} type="button">Hủy sửa</button>}
    </form><div className="teaching-table-wrap"><table><thead><tr><th>Ngày</th><th>Giờ</th><th>Lớp / Môn</th><th>Phòng</th><th>Thao tác</th></tr></thead><tbody>{schedules.map((s) => <tr key={s.id}><td>{weekdayName(s.weekday)}</td><td>{s.startTime.slice(0,5)}–{s.endTime.slice(0,5)}</td><td>{s.classCode} · {s.subjectName}</td><td>{s.room}</td><td><button disabled={busy} onClick={() => setEditSchedule(s)} type="button">Sửa lịch</button> <button disabled={busy} onClick={() => void execute(() => adminRequest(`/api/admin/schedules/${s.id}`, { method: 'DELETE' }), 'Đã xóa lịch học.')} type="button">Xóa lịch</button></td></tr>)}</tbody></table></div></section>
  </div>;
}
