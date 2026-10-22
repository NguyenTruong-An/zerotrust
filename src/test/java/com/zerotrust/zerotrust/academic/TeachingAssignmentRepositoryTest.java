package com.zerotrust.zerotrust.academic;

import com.zerotrust.zerotrust.entity.*;
import com.zerotrust.zerotrust.repository.*;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.data.domain.PageRequest;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest(showSql=false)
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace=AutoConfigureTestDatabase.Replace.NONE)
class TeachingAssignmentRepositoryTest {
    @Autowired EntityManager em;
    @Autowired TeachingAssignmentRepository assignments;
    @Autowired ScheduleEntryRepository schedules;
    @Autowired TeacherScoreRepository scores;

    @Test void assignmentTripleIsUnique() {
        var f=AcademicFixtures.graph(em);em.flush();
        var duplicate=new TeachingAssignmentEntity();duplicate.setTeacherEntity(f.teacher());
        duplicate.setStudentClassEntity(f.studentClass());duplicate.setSubjectEntity(f.subject());
        assertThrows(RuntimeException.class,()->assignments.saveAndFlush(duplicate));
    }
    @Test void scheduleCannotHaveReversedChronology() {
        var f=AcademicFixtures.graph(em);var s=AcademicFixtures.schedule(em,f.assignment(),LocalTime.of(10,0),LocalTime.of(9,0));
        assertThrows(RuntimeException.class,()->schedules.saveAndFlush(s));
    }
    @Test void referencedAssignmentCannotBeDeleted() {
        var f=AcademicFixtures.graph(em);AcademicFixtures.schedule(em,f.assignment(),LocalTime.of(9,0),LocalTime.of(10,0));em.flush();
        assertThrows(RuntimeException.class,()->{assignments.delete(f.assignment());assignments.flush();});
    }
    @Test void schedulesAreRestrictedToExactClassAndTeacher() {
        var a=AcademicFixtures.graph(em);var b=AcademicFixtures.graph(em);
        var expected=AcademicFixtures.schedule(em,a.assignment(),LocalTime.of(9,0),LocalTime.of(10,0));
        AcademicFixtures.schedule(em,b.assignment(),LocalTime.of(11,0),LocalTime.of(12,0));em.flush();em.clear();
        var byClass=schedules.findByAssignmentEntityStudentClassEntityIdOrderByWeekdayAscStartTimeAsc(a.studentClass().getId(),PageRequest.of(0,20));
        var byTeacher=schedules.findByAssignmentEntityTeacherEntityIdOrderByWeekdayAscStartTimeAsc(a.teacher().getId(),PageRequest.of(0,20));
        assertEquals(List.of(expected.getId()),byClass.stream().map(ScheduleEntryEntity::getId).toList());
        assertEquals(List.of(expected.getId()),byTeacher.stream().map(ScheduleEntryEntity::getId).toList());
    }
    @Test void originalStudentSubjectUniquenessStillSpansTerms() {
        var f=AcademicFixtures.graph(em);ScoreEntity first=AcademicFixtures.score(f,(short)1,"2026-2027");scores.saveAndFlush(first);
        ScoreEntity second=AcademicFixtures.score(f,(short)2,"2027-2028");
        assertThrows(RuntimeException.class,()->scores.saveAndFlush(second));
    }
}

/** Synthetic in-memory fixtures only; no external identity or storage calls. */
final class AcademicFixtures {
    record Graph(TeacherEntity teacher,StudentClassEntity studentClass,SubjectEntity subject,StudentEntity student,TeachingAssignmentEntity assignment) {}
    static String name(){return UUID.randomUUID().toString().replace("-","").substring(0,16);}
    static UserEntity user(EntityManager em) {
        String n=name();UserEntity u=new UserEntity();u.setKeycloakUserId(UUID.randomUUID());u.setUsername(n);u.setEmail(n+"@qa.invalid");u.setFirstName("Synthetic");u.setLastName(n);em.persist(u);return u;
    }
    static TeacherEntity teacher(EntityManager em) {TeacherEntity t=new TeacherEntity();t.setTeacherCode(name());t.setUserEntity(user(em));em.persist(t);return t;}
    static StudentClassEntity studentClass(EntityManager em) {
        String n=name();StudentClassEntity c=new StudentClassEntity();c.setClassCode(n);c.setClassName(n);c.setDepartment("QA");c.setCourseYears("2026-2030");em.persist(c);return c;
    }
    static SubjectEntity subject(EntityManager em) {
        String n=name();SubjectEntity s=new SubjectEntity();s.setSubjectCode(n);s.setSubjectName(n);s.setCredits((short)3);em.persist(s);return s;
    }
    static StudentEntity student(EntityManager em,StudentClassEntity c) {
        StudentEntity s=new StudentEntity();s.setUserEntity(user(em));s.setStudentCode(name());s.setDateOfBirth(LocalDate.of(2005,1,1));s.setGender("OTHER");s.setStudentClassEntity(c);em.persist(s);return s;
    }
    static TeachingAssignmentEntity assignment(EntityManager em,TeacherEntity t,StudentClassEntity c,SubjectEntity s) {
        TeachingAssignmentEntity a=new TeachingAssignmentEntity();a.setTeacherEntity(t);a.setStudentClassEntity(c);a.setSubjectEntity(s);em.persist(a);return a;
    }
    static Graph graph(EntityManager em) {
        TeacherEntity t=teacher(em);StudentClassEntity c=studentClass(em);SubjectEntity s=subject(em);StudentEntity student=student(em,c);
        return new Graph(t,c,s,student,assignment(em,t,c,s));
    }
    static ScheduleEntryEntity schedule(EntityManager em,TeachingAssignmentEntity a,LocalTime start,LocalTime end) {
        ScheduleEntryEntity s=new ScheduleEntryEntity();s.setAssignmentEntity(a);s.setWeekday(1);s.setStartTime(start);s.setEndTime(end);s.setRoom("QA");em.persist(s);return s;
    }
    static ScoreEntity score(Graph f,short semester,String year) {
        ScoreEntity s=new ScoreEntity();s.setStudentEntity(f.student());s.setSubjectEntity(f.subject());s.setSemester(semester);s.setAcademicYear(year);return s;
    }
}
