package com.zerotrust.zerotrust.academic;

import com.zerotrust.zerotrust.entity.*;
import com.zerotrust.zerotrust.exception.*;
import com.zerotrust.zerotrust.model.academic.TeachingRequests;
import com.zerotrust.zerotrust.repository.*;
import com.zerotrust.zerotrust.service.impl.TeacherAcademicService;
import jakarta.persistence.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import java.math.BigDecimal;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TeacherAcademicServiceTest {
    @Mock TeacherRepository teachers;@Mock TeachingAssignmentRepository assignments;@Mock ScheduleEntryRepository schedules;@Mock TeacherScoreRepository scores;@Mock EntityManager em;
    TeacherAcademicService service;TeacherEntity teacher;TeachingAssignmentEntity assignment;StudentEntity student;UUID subject;
    @BeforeEach void setup(){
        service=new TeacherAcademicService(teachers,assignments,schedules,scores);ReflectionTestUtils.setField(service,"em",em);
        subject=UUID.randomUUID();UserEntity u=new UserEntity();u.setId(UUID.randomUUID());u.setKeycloakUserId(subject);u.setStatus(UserEntity.Status.ACTIVE);
        teacher=new TeacherEntity();teacher.setId(UUID.randomUUID());teacher.setUserEntity(u);
        StudentClassEntity c=new StudentClassEntity();c.setId(UUID.randomUUID());
        SubjectEntity course=new SubjectEntity();course.setId(UUID.randomUUID());course.setSubjectCode("QA");course.setSubjectName("QA subject");
        assignment=new TeachingAssignmentEntity();assignment.setId(UUID.randomUUID());assignment.setTeacherEntity(teacher);assignment.setStudentClassEntity(c);assignment.setSubjectEntity(course);
        student=new StudentEntity();student.setId(UUID.randomUUID());student.setStudentCode("SYNTHETIC");student.setStudentClassEntity(c);student.setUserEntity(u);
        when(teachers.lockBySubject(subject)).thenReturn(Optional.of(teacher));
    }
    void allowed(){
        when(assignments.lockById(assignment.getId())).thenReturn(Optional.of(assignment));when(em.find(StudentEntity.class,student.getId())).thenReturn(student);
        when(em.find(UserEntity.class,student.getUserEntity().getId(),LockModeType.PESSIMISTIC_WRITE)).thenReturn(student.getUserEntity());
    }
    TeachingRequests.Grade grade(){return new TeachingRequests.Grade(new BigDecimal("8"),new BigDecimal("7"),new BigDecimal("9"),(short)1,"2026-2027");}
    @Test void ownedGradeUsesUnchangedFormulaAndImmutableLinks(){
        allowed();when(scores.lockByStudentAndSubject(student.getId(),assignment.getSubjectEntity().getId())).thenReturn(Optional.empty());
        when(scores.saveAndFlush(any())).thenAnswer(i->{ScoreEntity s=i.getArgument(0);s.setId(UUID.randomUUID());return s;});
        var result=service.grade(subject,assignment.getId(),student.getId(),grade());assertEquals(new BigDecimal("8.5"),result.totalScore());assertEquals("A",result.grade());
        assertEquals(student.getId(),result.studentId());assertEquals(assignment.getSubjectEntity().getId(),result.subjectId());verify(em).refresh(assignment,LockModeType.PESSIMISTIC_WRITE);
    }
    @Test void foreignAssignmentDeniedBeforeAnyStudentOrScoreRead(){
        TeacherEntity other=new TeacherEntity();other.setId(UUID.randomUUID());assignment.setTeacherEntity(other);
        when(assignments.lockById(assignment.getId())).thenReturn(Optional.of(assignment));
        assertThrows(WebException.class,()->service.grade(subject,assignment.getId(),student.getId(),grade()));verifyNoInteractions(scores);
    }
    @Test void foreignClassDeniedWithoutScoreMutation(){
        allowed();StudentClassEntity other=new StudentClassEntity();other.setId(UUID.randomUUID());student.setStudentClassEntity(other);
        assertThrows(WebException.class,()->service.grade(subject,assignment.getId(),student.getId(),grade()));verifyNoInteractions(scores);
    }
    @Test void inactiveTeacherDeniedBeforeAssignmentLookup(){
        teacher.getUserEntity().setStatus(UserEntity.Status.INACTIVE);
        WebException error=assertThrows(WebException.class,()->service.grade(subject,assignment.getId(),student.getId(),grade()));assertEquals(ErrorCode.USER_INACTIVE,error.getErrorCode());verifyNoInteractions(assignments,scores);
    }
    @Test void newGradeInvalidYearRejectedAndExistingMetadataNotChanged(){
        allowed();when(scores.lockByStudentAndSubject(any(),any())).thenReturn(Optional.empty());
        var bad=new TeachingRequests.Grade(BigDecimal.ONE,null,null,(short)1,"2026-2028");
        assertThrows(WebException.class,()->service.grade(subject,assignment.getId(),student.getId(),bad));verify(scores,never()).saveAndFlush(any());
    }
}
