'use client';

import { useCallback, useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { BookOpen, LogOut, ShieldCheck } from 'lucide-react';
import { AuthenticationExpiredError } from '../lib/api';
import { teacherMe, teacherAssignments, teacherSchedule, teacherRoster, saveTeacherGrade, weekdayName } from '../lib/teaching-api';
import type { Teacher, Assignment, Schedule, Roster } from '../lib/teaching-api';

export function TeacherDashboard({ username, onLogout, onAuthenticationExpired }: {
  username: string; onLogout: () => void; onAuthenticationExpired: () => void;
}) {
  const [profile, setProfile] = useState<Teacher | null>(null);
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [schedule, setSchedule] = useState<Schedule[]>([]);
  const [selected, setSelected] = useState('');
  const [roster, setRoster] = useState<Roster[]>([]);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const fail = useCallback((e: unknown) => {
    if (e instanceof AuthenticationExpiredError) onAuthenticationExpired();
    else setError(e instanceof Error ? e.message : 'Chưa thể tải dữ liệu.');
  }, [onAuthenticationExpired]);
  useEffect(() => {
    let active = true;
    Promise.all([teacherMe(), teacherAssignments(), teacherSchedule()]).then(([me, owned, times]) => {
      if (active) { setProfile(me); setAssignments(owned); setSchedule(times); }
    }).catch((e) => { if (active) fail(e); });
    return () => { active = false; };
  }, [fail]);
  const selectAssignment = async (id: string) => {
    setSelected(id); setRoster([]); setError(''); setNotice(''); setBusy(true);
    try { setRoster(await teacherRoster(id)); } catch (e) { fail(e); } finally { setBusy(false); }
  };
  const save = async (event: FormEvent<HTMLFormElement>, student: Roster) => {
    event.preventDefault(); const data = new FormData(event.currentTarget); setBusy(true); setError(''); setNotice('');
    const grade: Record<string, unknown> = {};
    for (const key of ['attendanceScore', 'midtermScore', 'finalScore']) {
      const value = String(data.get(key) ?? ''); if (value !== '') grade[key] = Number(value);
    }
    if (!student.score) { grade.semester = Number(data.get('semester')); grade.academicYear = String(data.get('academicYear')); }
    try { await saveTeacherGrade(selected, student.studentId, grade); setRoster(await teacherRoster(selected)); setNotice(`Đã lưu điểm ${student.studentCode}.`); }
    catch (e) { fail(e); } finally { setBusy(false); }
  };
  return <main className="teaching-shell" data-testid="teacher-dashboard">
    <header className="teaching-top"><div><p className="eyebrow"><ShieldCheck size={16} /> ZeroTrust · TEACHER</p><h1>Không gian giảng viên</h1><p>{profile ? `${profile.firstName} ${profile.lastName} · ${profile.teacherCode}` : username}</p></div><button onClick={onLogout} type="button"><LogOut size={17} /> Đăng xuất</button></header>
    {error && <p className="teaching-error" role="alert">{error}</p>}{notice && <p className="teaching-notice" role="status">{notice}</p>}
    <section className="teaching-card"><h2><BookOpen size={20} /> Lớp và môn được phân công</h2><p>Chọn một phân công để xem danh sách và cập nhật điểm trong phạm vi được giao.</p>
      <div className="teaching-assignments">{assignments.map((a) => <button aria-pressed={selected === a.id} disabled={busy} key={a.id} onClick={() => void selectAssignment(a.id)} type="button" data-assignment-id={a.id}><strong>{a.classCode}</strong><span>{a.subjectCode} · {a.subjectName}</span></button>)}{!assignments.length && <p>Chưa có phân công giảng dạy.</p>}</div>
    </section>
    {selected && <section className="teaching-card" aria-busy={busy}><h2>Danh sách sinh viên và điểm</h2><p>Liên kết sinh viên, môn học và kỳ của bản ghi hiện có không thay đổi khi giảng viên sửa điểm.</p>
      {roster.map((student) => <form className="teaching-grade" key={`${student.studentId}-${student.score?.attendanceScore}-${student.score?.midtermScore}-${student.score?.finalScore}`} onSubmit={(e) => void save(e, student)} data-student-id={student.studentId}>
        <div><strong>{student.studentCode}</strong><p>{student.firstName} {student.lastName}</p><small>Tổng: {student.score?.totalScore ?? '—'} · {student.score?.grade ?? 'Chưa đủ điểm'}</small></div>
        <label>Chuyên cần<input name="attendanceScore" aria-label={`Chuyên cần ${student.studentCode}`} type="number" min="0" max="10" step="0.01" defaultValue={student.score?.attendanceScore ?? ''} /></label>
        <label>Giữa kỳ<input name="midtermScore" aria-label={`Giữa kỳ ${student.studentCode}`} type="number" min="0" max="10" step="0.01" defaultValue={student.score?.midtermScore ?? ''} /></label>
        <label>Cuối kỳ<input name="finalScore" aria-label={`Cuối kỳ ${student.studentCode}`} type="number" min="0" max="10" step="0.01" defaultValue={student.score?.finalScore ?? ''} /></label>
        {!student.score && <><label>Học kỳ<select name="semester"><option value="1">1</option><option value="2">2</option></select></label><label>Năm học<input name="academicYear" placeholder="2026-2027" pattern="[0-9]{4}-[0-9]{4}" required /></label></>}
        <button type="submit" disabled={busy}>Lưu điểm</button>
      </form>)}{!roster.length && !busy && <p>Chưa có sinh viên đang hoạt động trong lớp này.</p>}
    </section>}
    <section className="teaching-card"><h2>Lịch giảng dạy</h2><div className="teaching-table-wrap"><table><thead><tr><th>Ngày</th><th>Giờ</th><th>Lớp</th><th>Môn học</th><th>Phòng</th></tr></thead><tbody>{schedule.map((s) => <tr key={s.id}><td>{weekdayName(s.weekday)}</td><td>{s.startTime.slice(0,5)}–{s.endTime.slice(0,5)}</td><td>{s.classCode}</td><td>{s.subjectName}</td><td>{s.room}</td></tr>)}</tbody></table></div>{!schedule.length && <p>Chưa có lịch giảng dạy.</p>}</section>
  </main>;
}
