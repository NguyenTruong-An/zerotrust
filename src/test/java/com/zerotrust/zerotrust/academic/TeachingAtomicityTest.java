package com.zerotrust.zerotrust.academic;

import com.zerotrust.zerotrust.entity.*;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.identity.IdentityProviderGateway;
import com.zerotrust.zerotrust.model.academic.TeachingRequests;
import com.zerotrust.zerotrust.repository.*;
import com.zerotrust.zerotrust.service.impl.*;
import jakarta.persistence.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.*;
import org.springframework.transaction.support.TransactionTemplate;
import java.math.BigDecimal;
import java.time.LocalTime;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties="spring.datasource.url=jdbc:h2:mem:qa02c-atomic;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE")
@AutoConfigureMockMvc @ActiveProfiles("test")
class TeachingAtomicityTest {
    @Autowired EntityManager em;@Autowired PlatformTransactionManager manager;@Autowired TeacherAcademicService academic;
    @Autowired StudentScheduleService studentSchedule;@Autowired TeacherScoreRepository scores;@Autowired MockMvc mvc;
    @MockitoBean IdentityProviderGateway identity;
    TransactionTemplate tx(){return new TransactionTemplate(manager);}
    AcademicFixtures.Graph seed(){return tx().execute(s->{var f=AcademicFixtures.graph(em);em.flush();return f;});}
    TeachingRequests.Grade grade(){return new TeachingRequests.Grade(new BigDecimal("8"),new BigDecimal("7"),new BigDecimal("9"),(short)1,"2026-2027");}
    UUID subject(AcademicFixtures.Graph f){return f.teacher().getUserEntity().getKeycloakUserId();}
    @Test @WithMockUser(roles="TEACHER") void ownedGradeCommitsAndReloadsUnchangedCalculation(){
        var f=seed();var saved=academic.grade(subject(f),f.assignment().getId(),f.student().getId(),grade());
        tx().executeWithoutResult(s->{em.clear();var row=em.find(ScoreEntity.class,saved.id());assertEquals(0,new BigDecimal("8.5").compareTo(row.getTotalScore()));assertEquals("A",row.getGrade());assertEquals(f.subject().getId(),row.getSubjectEntity().getId());});
    }
    @Test @WithMockUser(roles="TEACHER") void foreignAssignmentDenialLeavesAllScoresUnchanged(){
        var a=seed();var b=seed();long before=scores.count();
        assertThrows(WebException.class,()->academic.grade(subject(a),b.assignment().getId(),b.student().getId(),grade()));assertEquals(before,scores.count());
    }
    @Test @WithMockUser(roles="TEACHER") void foreignClassDenialLeavesAllScoresUnchanged(){
        var a=seed();var b=seed();long before=scores.count();
        assertThrows(WebException.class,()->academic.grade(subject(a),a.assignment().getId(),b.student().getId(),grade()));assertEquals(before,scores.count());
    }
    @Test @WithMockUser(roles="TEACHER") void flushedGradeRollsBackWhenTransactionFails(){
        var f=seed();long before=scores.count();
        assertThrows(IllegalStateException.class,()->tx().executeWithoutResult(s->{academic.grade(subject(f),f.assignment().getId(),f.student().getId(),grade());assertTrue(scores.findByStudentEntityIdAndSubjectEntityId(f.student().getId(),f.subject().getId()).isPresent());throw new IllegalStateException("controlled rollback");}));
        assertEquals(before,scores.count());assertTrue(scores.findByStudentEntityIdAndSubjectEntityId(f.student().getId(),f.subject().getId()).isEmpty());
    }
    @Test @WithMockUser(roles="TEACHER") void cachedAssignmentCannotAuthorizeAfterReassignment(){
        var a=seed();var b=seed();long before=scores.count();
        assertThrows(WebException.class,()->tx().executeWithoutResult(s->{
            var cached=em.find(TeachingAssignmentEntity.class,a.assignment().getId());assertEquals(a.teacher().getId(),cached.getTeacherEntity().getId());
            var separate=tx();separate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
            separate.executeWithoutResult(n->{var row=em.find(TeachingAssignmentEntity.class,a.assignment().getId());row.setTeacherEntity(em.getReference(TeacherEntity.class,b.teacher().getId()));em.flush();});
            academic.grade(subject(a),a.assignment().getId(),a.student().getId(),grade());
        }));assertEquals(before,scores.count());
    }
    @Test @WithMockUser(roles="STUDENT") void studentScheduleUsesOwnClassAfterReload(){
        var a=seed();var b=seed();tx().executeWithoutResult(s->{AcademicFixtures.schedule(em,em.getReference(TeachingAssignmentEntity.class,a.assignment().getId()),LocalTime.of(9,0),LocalTime.of(10,0));AcademicFixtures.schedule(em,em.getReference(TeachingAssignmentEntity.class,b.assignment().getId()),LocalTime.of(11,0),LocalTime.of(12,0));});
        var rows=studentSchedule.current(a.student().getUserEntity().getKeycloakUserId());assertEquals(1,rows.size());assertEquals(a.assignment().getId(),rows.get(0).assignmentId());
    }
    @Test @WithMockUser(roles="ADMIN") void existingCatalogDeleteCannotOrphanAssignment() throws Exception {
        UUID id=tx().execute(s->{var c=AcademicFixtures.studentClass(em);AcademicFixtures.assignment(em,AcademicFixtures.teacher(em),c,AcademicFixtures.subject(em));return c.getId();});
        mvc.perform(delete("/api/admin/student-classes/"+id)).andExpect(status().isConflict());
        tx().executeWithoutResult(s->{assertNotNull(em.find(StudentClassEntity.class,id));assertEquals(1L,em.createQuery("select count(a) from TeachingAssignmentEntity a where a.studentClassEntity.id=:id",Long.class).setParameter("id",id).getSingleResult());});
    }
    @Test @WithMockUser(roles="ADMIN") void assignmentDeleteCannotOrphanSchedule() throws Exception {
        var f=seed();tx().executeWithoutResult(s->AcademicFixtures.schedule(em,em.getReference(TeachingAssignmentEntity.class,f.assignment().getId()),LocalTime.of(9,0),LocalTime.of(10,0)));
        mvc.perform(delete("/api/admin/teaching-assignments/"+f.assignment().getId())).andExpect(status().isConflict());
        tx().executeWithoutResult(s->assertNotNull(em.find(TeachingAssignmentEntity.class,f.assignment().getId())));
    }
    @Test @WithMockUser(roles="ADMIN") void referencedDeleteRetainsBothParentsAndSchedules() throws Exception {
        var a=seed();var b=seed();UUID[] scheduleIds=tx().execute(s->new UUID[]{
                AcademicFixtures.schedule(em,em.getReference(TeachingAssignmentEntity.class,a.assignment().getId()),LocalTime.of(9,0),LocalTime.of(10,0)).getId(),
                AcademicFixtures.schedule(em,em.getReference(TeachingAssignmentEntity.class,b.assignment().getId()),LocalTime.of(11,0),LocalTime.of(12,0)).getId()});
        long[] counts=tx().execute(s->new long[]{em.createQuery("select count(a) from TeachingAssignmentEntity a",Long.class).getSingleResult(),em.createQuery("select count(s) from ScheduleEntryEntity s",Long.class).getSingleResult()});
        mvc.perform(delete("/api/admin/teaching-assignments/"+a.assignment().getId())).andExpect(status().isConflict());
        tx().executeWithoutResult(s->{
            assertNotNull(em.find(TeachingAssignmentEntity.class,a.assignment().getId()));assertNotNull(em.find(TeachingAssignmentEntity.class,b.assignment().getId()));
            assertEquals(a.assignment().getId(),em.find(ScheduleEntryEntity.class,scheduleIds[0]).getAssignmentEntity().getId());
            assertEquals(b.assignment().getId(),em.find(ScheduleEntryEntity.class,scheduleIds[1]).getAssignmentEntity().getId());
            assertEquals(counts[0],em.createQuery("select count(a) from TeachingAssignmentEntity a",Long.class).getSingleResult());
            assertEquals(counts[1],em.createQuery("select count(s) from ScheduleEntryEntity s",Long.class).getSingleResult());
        });
    }
    @Test @WithMockUser(roles="ADMIN") void unreferencedDeleteCommitsWithoutDeletingUnrelatedRows() throws Exception {
        var a=seed();var b=seed();UUID schedule=tx().execute(s->AcademicFixtures.schedule(em,em.getReference(TeachingAssignmentEntity.class,b.assignment().getId()),LocalTime.of(9,0),LocalTime.of(10,0)).getId());
        mvc.perform(delete("/api/admin/teaching-assignments/"+a.assignment().getId())).andExpect(status().isNoContent());
        tx().executeWithoutResult(s->{assertNull(em.find(TeachingAssignmentEntity.class,a.assignment().getId()));assertNotNull(em.find(TeachingAssignmentEntity.class,b.assignment().getId()));assertNotNull(em.find(ScheduleEntryEntity.class,schedule));});
    }
}
