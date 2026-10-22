package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.*;
import com.zerotrust.zerotrust.exception.*;
import com.zerotrust.zerotrust.model.academic.*;
import com.zerotrust.zerotrust.model.response.ScoreResponseDTO;
import com.zerotrust.zerotrust.repository.*;
import jakarta.persistence.*;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.*;

@Service @RequiredArgsConstructor
@PreAuthorize("hasRole('TEACHER')")
public class TeacherAcademicService {
    private final TeacherRepository teachers;
    private final TeachingAssignmentRepository assignments;
    private final ScheduleEntryRepository schedules;
    private final TeacherScoreRepository scores;
    @PersistenceContext private EntityManager em;

    @Transactional(readOnly = true)
    public TeachingResponses.Teacher me(UUID subject) { return TeachingResponses.teacher(activeTeacher(subject, false)); }
    @Transactional(readOnly = true)
    public List<TeachingResponses.Assignment> assignments(UUID subject) {
        TeacherEntity t = activeTeacher(subject, false);
        return assignments.findByTeacherEntityIdOrderById(t.getId(), PageRequest.of(0,100))
                .stream().map(TeachingResponses::assignment).toList();
    }
    @Transactional(readOnly = true)
    public List<TeachingResponses.Schedule> schedule(UUID subject) {
        TeacherEntity t = activeTeacher(subject, false);
        return schedules.findByAssignmentEntityTeacherEntityIdOrderByWeekdayAscStartTimeAsc(t.getId(), PageRequest.of(0,200))
                .stream().map(TeachingResponses::schedule).toList();
    }
    @Transactional(readOnly = true)
    public List<TeachingResponses.Roster> roster(UUID subject, UUID assignmentId) {
        TeacherEntity t = activeTeacher(subject, false);
        TeachingAssignmentEntity a = own(t, assignments.findById(assignmentId).orElseThrow(TeacherAcademicService::missing));
        return em.createQuery("select s from StudentEntity s join fetch s.userEntity where s.studentClassEntity.id = :classId and s.userEntity.status = :active order by s.studentCode", StudentEntity.class)
                .setParameter("classId",a.getStudentClassEntity().getId()).setParameter("active",UserEntity.Status.ACTIVE)
                .setMaxResults(200).getResultList().stream().map(s -> new TeachingResponses.Roster(
                        s.getId(),s.getStudentCode(),s.getUserEntity().getFirstName(),s.getUserEntity().getLastName(),
                        scores.findByStudentEntityIdAndSubjectEntityId(s.getId(),a.getSubjectEntity().getId())
                                .map(TeachingResponses::score).orElse(null))).toList();
    }
    @Transactional
    public ScoreResponseDTO grade(UUID subject, UUID assignmentId, UUID studentId, TeachingRequests.Grade request) {
        // Both authorization rows are current locked reads and held until score commit.
        TeacherEntity t = activeTeacher(subject, true);
        TeachingAssignmentEntity a = assignments.lockById(assignmentId).orElseThrow(TeacherAcademicService::missing);
        em.refresh(a,LockModeType.PESSIMISTIC_WRITE);own(t,a);
        StudentEntity s = em.find(StudentEntity.class, studentId);
        if (s == null) throw missing();
        UserEntity account = em.find(UserEntity.class, s.getUserEntity().getId(), LockModeType.PESSIMISTIC_WRITE);
        em.refresh(account, LockModeType.PESSIMISTIC_WRITE);
        em.refresh(s, LockModeType.PESSIMISTIC_WRITE);
        if (!s.getStudentClassEntity().getId().equals(a.getStudentClassEntity().getId())) throw missing();
        if (account.getStatus() != UserEntity.Status.ACTIVE) throw new WebException(ErrorCode.USER_INACTIVE);
        ScoreEntity score = scores.lockByStudentAndSubject(studentId,a.getSubjectEntity().getId()).orElse(null);
        if (request.attendanceScore()==null && request.midtermScore()==null && request.finalScore()==null)
            throw new WebException(ErrorCode.INVALID_REQUEST,"At least one grade component is required");
        if (score == null) {
            if (request.semester()==null || request.academicYear()==null) throw new WebException(ErrorCode.INVALID_REQUEST,"Semester and academic year are required for a new grade");
            validateYear(request.academicYear());
            score = new ScoreEntity();score.setStudentEntity(s);score.setSubjectEntity(a.getSubjectEntity());
            score.setSemester(request.semester());score.setAcademicYear(request.academicYear());
        } else if ((request.semester()!=null && !request.semester().equals(score.getSemester()))
                || (request.academicYear()!=null && !request.academicYear().equals(score.getAcademicYear()))) {
            throw new WebException(ErrorCode.INVALID_REQUEST,"Teacher grade updates cannot change academic metadata");
        }
        if (request.attendanceScore()!=null) score.setAttendanceScore(request.attendanceScore());
        if (request.midtermScore()!=null) score.setMidtermScore(request.midtermScore());
        if (request.finalScore()!=null) score.setFinalScore(request.finalScore());
        if (score.getAttendanceScore()!=null && score.getMidtermScore()!=null && score.getFinalScore()!=null) {
            ScoreCalculator.Result calculated=ScoreCalculator.calculate(score.getAttendanceScore(),score.getMidtermScore(),score.getFinalScore());
            score.setTotalScore(calculated.totalScore());score.setGrade(calculated.grade());
        } else { score.setTotalScore(null);score.setGrade(null); }
        return TeachingResponses.score(scores.saveAndFlush(score));
    }
    private TeacherEntity activeTeacher(UUID subject, boolean lock) {
        TeacherEntity t = (lock ? teachers.lockBySubject(subject) : teachers.findByUserEntityKeycloakUserId(subject)).orElseThrow(TeacherAcademicService::missing);
        if (lock) { em.refresh(t,LockModeType.PESSIMISTIC_WRITE);em.refresh(t.getUserEntity(),LockModeType.PESSIMISTIC_WRITE); }
        if (t.getUserEntity().getStatus()!=UserEntity.Status.ACTIVE) throw new WebException(ErrorCode.USER_INACTIVE);
        return t;
    }
    private TeachingAssignmentEntity own(TeacherEntity t, TeachingAssignmentEntity a) {
        if (!t.getId().equals(a.getTeacherEntity().getId())) throw missing();
        return a;
    }
    private static WebException missing() { return new WebException(ErrorCode.USER_NOT_FOUND,"Teaching resource not found"); }
    private static void validateYear(String year) {
        if (!year.matches("\\d{4}-\\d{4}") || Integer.parseInt(year.substring(5))!=Integer.parseInt(year.substring(0,4))+1)
            throw new WebException(ErrorCode.INVALID_REQUEST,"Academic year must span two consecutive years");
    }
}
