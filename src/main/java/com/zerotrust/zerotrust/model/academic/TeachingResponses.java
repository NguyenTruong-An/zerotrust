package com.zerotrust.zerotrust.model.academic;

import com.zerotrust.zerotrust.entity.*;
import com.zerotrust.zerotrust.model.response.ScoreResponseDTO;
import java.time.LocalTime;
import java.util.UUID;

public final class TeachingResponses {
    private TeachingResponses() { }
    public record Teacher(UUID id, UUID userId, UUID keycloakUserId, String teacherCode,
            String username, String firstName, String lastName, String email, String status) { }
    public record Assignment(UUID id, UUID teacherId, String teacherName, UUID classId,
            String classCode, UUID subjectId, String subjectCode, String subjectName) { }
    public record Schedule(UUID id, UUID assignmentId, UUID classId, String classCode,
            UUID subjectId, String subjectName, String teacherName, int weekday,
            LocalTime startTime, LocalTime endTime, String room) { }
    public record Roster(UUID studentId, String studentCode, String firstName, String lastName, ScoreResponseDTO score) { }
    public static Teacher teacher(TeacherEntity t) {
        UserEntity u = t.getUserEntity();
        return new Teacher(t.getId(), u.getId(), u.getKeycloakUserId(), t.getTeacherCode(),
                u.getUsername(), u.getFirstName(), u.getLastName(), u.getEmail(), u.getStatus().name());
    }
    public static Assignment assignment(TeachingAssignmentEntity a) {
        UserEntity u = a.getTeacherEntity().getUserEntity();
        return new Assignment(a.getId(), a.getTeacherEntity().getId(), u.getFirstName()+" "+u.getLastName(),
                a.getStudentClassEntity().getId(), a.getStudentClassEntity().getClassCode(),
                a.getSubjectEntity().getId(), a.getSubjectEntity().getSubjectCode(), a.getSubjectEntity().getSubjectName());
    }
    public static Schedule schedule(ScheduleEntryEntity s) {
        Assignment a = assignment(s.getAssignmentEntity());
        return new Schedule(s.getId(), a.id(), a.classId(), a.classCode(), a.subjectId(),
                a.subjectName(), a.teacherName(), s.getWeekday(), s.getStartTime(), s.getEndTime(), s.getRoom());
    }
    public static ScoreResponseDTO score(ScoreEntity s) {
        return new ScoreResponseDTO(s.getId(), s.getStudentEntity().getId(), s.getStudentEntity().getStudentCode(),
                s.getSubjectEntity().getId(), s.getSubjectEntity().getSubjectCode(), s.getSubjectEntity().getSubjectName(),
                s.getSemester(), s.getAcademicYear(), s.getAttendanceScore(), s.getMidtermScore(), s.getFinalScore(), s.getTotalScore(), s.getGrade());
    }
}
