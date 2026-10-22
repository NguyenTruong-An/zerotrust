import { portalRequest } from './admin-api';
import type { Score } from './admin-api';

export type Teacher = {
  id: string; userId: string; keycloakUserId: string; teacherCode: string;
  username: string; firstName: string; lastName: string; email: string; status: string;
};
export type Assignment = {
  id: string; teacherId: string; teacherName: string; classId: string;
  classCode: string; subjectId: string; subjectCode: string; subjectName: string;
};
export type Schedule = {
  id: string; assignmentId: string; classId: string; classCode: string; subjectId: string;
  subjectName: string; teacherName: string; weekday: number; startTime: string; endTime: string; room: string;
};
export type Roster = { studentId: string; studentCode: string; firstName: string; lastName: string; score: Score | null };
export const weekdayName = (day: number) => ['Thứ hai', 'Thứ ba', 'Thứ tư', 'Thứ năm', 'Thứ sáu', 'Thứ bảy', 'Chủ nhật'][day - 1] ?? '—';
export const studentSchedule = () => portalRequest<Schedule[]>('/api/students/me/schedule');
export const teacherMe = () => portalRequest<Teacher>('/api/teachers/me');
export const teacherAssignments = () => portalRequest<Assignment[]>('/api/teachers/me/assignments');
export const teacherSchedule = () => portalRequest<Schedule[]>('/api/teachers/me/schedule');
export const teacherRoster = (id: string) => portalRequest<Roster[]>(`/api/teachers/assignments/${encodeURIComponent(id)}/students`);
export function saveTeacherGrade(assignment: string, student: string, grade: Record<string, unknown>) {
  return portalRequest<Score>(`/api/teachers/assignments/${encodeURIComponent(assignment)}/students/${encodeURIComponent(student)}/score`, {
    method: 'PATCH', body: JSON.stringify(grade),
  });
}
