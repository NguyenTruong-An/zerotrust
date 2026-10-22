package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.*;
import com.zerotrust.zerotrust.exception.*;
import com.zerotrust.zerotrust.identity.IdentityProviderGateway;
import com.zerotrust.zerotrust.identity.model.*;
import com.zerotrust.zerotrust.model.academic.*;
import com.zerotrust.zerotrust.repository.*;
import jakarta.persistence.*;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

@Service @RequiredArgsConstructor @PreAuthorize("hasRole('ADMIN')")
public class TeachingAdministrationService {
    private final TeacherRepository teachers;
    private final TeachingAssignmentRepository assignments;
    private final ScheduleEntryRepository schedules;
    private final UserRepository users;
    private final IdentityProviderGateway identity;
    private final PlatformTransactionManager transactionManager;
    @PersistenceContext private EntityManager em;

    public TeachingResponses.Teacher createTeacher(TeachingRequests.TeacherCreate r) {
        if (users.existsByUsernameIgnoreCase(r.username().trim())) throw new WebException(ErrorCode.USERNAME_EXISTS);
        if (users.existsByEmailIgnoreCase(r.email().trim())) throw new WebException(ErrorCode.EMAIL_EXISTS);
        if (teachers.existsByTeacherCodeIgnoreCase(r.teacherCode().trim())) throw new WebException(ErrorCode.INVALID_REQUEST,"Teacher code already exists");
        ProvisionedIdentityUser provisioned=identity.createUser(new CreateIdentityUserCommand(r.username().trim(),r.password(),r.email().trim().toLowerCase(Locale.ROOT),r.firstName().trim(),r.lastName().trim()));
        try {
            identity.assignRealmRole(provisioned.userId(),"TEACHER");
            return transaction().execute(status -> {
                UserEntity u=new UserEntity();u.setKeycloakUserId(provisioned.userId());u.setUsername(r.username().trim());
                u.setEmail(r.email().trim().toLowerCase(Locale.ROOT));u.setFirstName(r.firstName().trim());u.setLastName(r.lastName().trim());
                users.saveAndFlush(u);
                TeacherEntity t=new TeacherEntity();t.setUserEntity(u);t.setTeacherCode(r.teacherCode().trim().toUpperCase(Locale.ROOT));
                return TeachingResponses.teacher(teachers.saveAndFlush(t));
            });
        } catch (RuntimeException failure) { identity.deleteUserQuietly(provisioned);throw failure; }
    }
    public TeachingResponses.Teacher updateTeacher(UUID id, TeachingRequests.TeacherUpdate r) {
        AtomicReference<IdentityUserProfileSnapshot> snapshot=new AtomicReference<>();AtomicReference<UUID> subject=new AtomicReference<>();
        try {
            return transaction().execute(status -> {
                TeacherEntity t=lockedTeacher(id);UserEntity u=t.getUserEntity();subject.set(u.getKeycloakUserId());
                if (users.existsByEmailIgnoreCaseAndIdNot(r.email().trim(),u.getId()) || teachers.existsByTeacherCodeIgnoreCaseAndIdNot(r.teacherCode().trim(),id))
                    throw new WebException(ErrorCode.INVALID_REQUEST,"Teacher code or email already exists");
                snapshot.set(identity.updateUserProfile(u.getKeycloakUserId(),r.firstName().trim(),r.lastName().trim(),r.email().trim().toLowerCase(Locale.ROOT)));
                u.setFirstName(r.firstName().trim());u.setLastName(r.lastName().trim());u.setEmail(r.email().trim().toLowerCase(Locale.ROOT));
                u.setStatus(UserEntity.Status.valueOf(r.status()));t.setTeacherCode(r.teacherCode().trim().toUpperCase(Locale.ROOT));
                users.saveAndFlush(u);return TeachingResponses.teacher(teachers.saveAndFlush(t));
            });
        } catch (RuntimeException failure) {
            if (snapshot.get()!=null) identity.restoreUserProfileQuietly(subject.get(),snapshot.get());
            throw failure;
        }
    }
    @Transactional(readOnly = true)
    public List<TeachingResponses.Teacher> teachers() { return teachers.findAll(PageRequest.of(0,100)).stream().map(TeachingResponses::teacher).toList(); }
    @Transactional(readOnly = true)
    public List<TeachingResponses.Assignment> assignments() { return assignments.findAll(PageRequest.of(0,100)).stream().map(TeachingResponses::assignment).toList(); }
    @Transactional(readOnly = true)
    public List<TeachingResponses.Schedule> schedules() { return schedules.findAll(PageRequest.of(0,200)).stream().map(TeachingResponses::schedule).toList(); }
    @Transactional
    public TeachingResponses.Assignment createAssignment(TeachingRequests.Assignment r) {
        TeacherEntity t=lockedTeacher(r.teacherId());requireActive(t);
        TeachingAssignmentEntity a=new TeachingAssignmentEntity();setAssignment(a,t,r);
        return TeachingResponses.assignment(assignments.saveAndFlush(a));
    }
    @Transactional
    public TeachingResponses.Assignment updateAssignment(UUID id, TeachingRequests.Assignment r) {
        UUID previous=assignments.findById(id).orElseThrow(TeachingAdministrationService::missing).getTeacherEntity().getId();
        List<UUID> ids=new ArrayList<>(new HashSet<>(List.of(previous,r.teacherId())));ids.sort(UUID::compareTo);
        for (UUID teacherId:ids) lockedTeacher(teacherId);
        TeachingAssignmentEntity a=assignments.lockById(id).orElseThrow(TeachingAdministrationService::missing);
        em.refresh(a,LockModeType.PESSIMISTIC_WRITE);
        if (!a.getTeacherEntity().getId().equals(previous)) throw new WebException(ErrorCode.INVALID_REQUEST,"Assignment changed; reload before editing");
        TeacherEntity t=lockedTeacher(r.teacherId());requireActive(t);setAssignment(a,t,r);
        return TeachingResponses.assignment(assignments.saveAndFlush(a));
    }
    @Transactional
    public void deleteAssignment(UUID id) { TeachingAssignmentEntity a=lockedAssignment(id);assignments.delete(a);assignments.flush(); }
    @Transactional
    public TeachingResponses.Schedule createSchedule(TeachingRequests.Schedule r) {
        TeachingAssignmentEntity a=lockedAssignment(r.assignmentId());ScheduleEntryEntity s=new ScheduleEntryEntity();setSchedule(s,a,r);
        return TeachingResponses.schedule(schedules.saveAndFlush(s));
    }
    @Transactional
    public TeachingResponses.Schedule updateSchedule(UUID id, TeachingRequests.Schedule r) {
        ScheduleEntryEntity current=schedules.findById(id).orElseThrow(TeachingAdministrationService::missing);
        if (!current.getAssignmentEntity().getId().equals(r.assignmentId())) throw new WebException(ErrorCode.INVALID_REQUEST,"A schedule cannot move between assignments");
        TeachingAssignmentEntity a=lockedAssignment(r.assignmentId());ScheduleEntryEntity s=em.find(ScheduleEntryEntity.class,id,LockModeType.PESSIMISTIC_WRITE);
        if (s==null) throw missing();em.refresh(s,LockModeType.PESSIMISTIC_WRITE);setSchedule(s,a,r);
        return TeachingResponses.schedule(schedules.saveAndFlush(s));
    }
    @Transactional
    public void deleteSchedule(UUID id) {
        ScheduleEntryEntity current=schedules.findById(id).orElseThrow(TeachingAdministrationService::missing);
        lockedAssignment(current.getAssignmentEntity().getId());
        ScheduleEntryEntity s=em.find(ScheduleEntryEntity.class,id,LockModeType.PESSIMISTIC_WRITE);
        if (s==null) throw missing();schedules.delete(s);schedules.flush();
    }
    private void setAssignment(TeachingAssignmentEntity a,TeacherEntity t,TeachingRequests.Assignment r) {
        StudentClassEntity c=em.find(StudentClassEntity.class,r.classId(),LockModeType.PESSIMISTIC_WRITE);
        SubjectEntity s=em.find(SubjectEntity.class,r.subjectId(),LockModeType.PESSIMISTIC_WRITE);
        if (c==null || s==null) throw new WebException(ErrorCode.INVALID_REQUEST,"Class or subject not found");
        a.setTeacherEntity(t);a.setStudentClassEntity(c);a.setSubjectEntity(s);
    }
    private void setSchedule(ScheduleEntryEntity s,TeachingAssignmentEntity a,TeachingRequests.Schedule r) {
        if (r.startTime()==null || r.endTime()==null || !r.startTime().isBefore(r.endTime()) || r.weekday()<1 || r.weekday()>7)
            throw new WebException(ErrorCode.INVALID_REQUEST,"Invalid schedule time range");
        s.setAssignmentEntity(a);s.setWeekday(r.weekday());s.setStartTime(r.startTime());s.setEndTime(r.endTime());s.setRoom(r.room().trim());
    }
    private TeachingAssignmentEntity lockedAssignment(UUID id) {
        TeachingAssignmentEntity original=assignments.findById(id).orElseThrow(TeachingAdministrationService::missing);
        UUID owner=original.getTeacherEntity().getId();lockedTeacher(owner);
        TeachingAssignmentEntity a=assignments.lockById(id).orElseThrow(TeachingAdministrationService::missing);em.refresh(a,LockModeType.PESSIMISTIC_WRITE);
        if (!a.getTeacherEntity().getId().equals(owner)) throw new WebException(ErrorCode.INVALID_REQUEST,"Assignment changed; retry after reload");
        return a;
    }
    private TeacherEntity lockedTeacher(UUID id) { return teachers.lockById(id).orElseThrow(TeachingAdministrationService::missing); }
    private void requireActive(TeacherEntity t) { if (t.getUserEntity().getStatus()!=UserEntity.Status.ACTIVE) throw new WebException(ErrorCode.USER_INACTIVE); }
    private static WebException missing() { return new WebException(ErrorCode.USER_NOT_FOUND,"Teaching resource not found"); }
    private TransactionTemplate transaction() { TransactionTemplate t=new TransactionTemplate(transactionManager);t.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);return t; }
}
