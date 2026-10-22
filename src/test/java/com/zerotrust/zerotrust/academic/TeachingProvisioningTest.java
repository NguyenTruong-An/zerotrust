package com.zerotrust.zerotrust.academic;

import com.zerotrust.zerotrust.entity.*;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.identity.IdentityProviderGateway;
import com.zerotrust.zerotrust.identity.model.ProvisionedIdentityUser;
import com.zerotrust.zerotrust.model.academic.TeachingRequests;
import com.zerotrust.zerotrust.repository.*;
import com.zerotrust.zerotrust.service.impl.TeachingAdministrationService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.*;
import org.springframework.transaction.support.SimpleTransactionStatus;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TeachingProvisioningTest {
    @Mock TeacherRepository teachers;@Mock TeachingAssignmentRepository assignments;@Mock ScheduleEntryRepository schedules;
    @Mock UserRepository users;@Mock IdentityProviderGateway identity;@Mock PlatformTransactionManager manager;
    TeachingAdministrationService service;
    final ProvisionedIdentityUser provisioned=new ProvisionedIdentityUser(UUID.randomUUID());
    TeachingRequests.TeacherCreate request(){return new TeachingRequests.TeacherCreate("qa.teacher","synthetic-password","teacher@qa.invalid","QA","Teacher","T-QA");}
    @BeforeEach void setup(){service=new TeachingAdministrationService(teachers,assignments,schedules,users,identity,manager);}
    void remoteCreated(){when(identity.createUser(any())).thenReturn(provisioned);}
    void transaction(){when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());}
    @Test void createAssignsOnlyTeacherRoleAndCommitsLocalAssociation(){
        remoteCreated();transaction();
        when(users.saveAndFlush(any())).thenAnswer(i->{UserEntity u=i.getArgument(0);u.setId(UUID.randomUUID());return u;});
        when(teachers.saveAndFlush(any())).thenAnswer(i->{TeacherEntity t=i.getArgument(0);t.setId(UUID.randomUUID());return t;});
        var result=service.createTeacher(request());assertEquals(provisioned.userId(),result.keycloakUserId());
        verify(identity).assignRealmRole(provisioned.userId(),"TEACHER");verify(manager).commit(any());verify(identity,never()).deleteUserQuietly(any());
        assertFalse(request().toString().contains("synthetic-password"));
    }
    @Test void roleFailureCompensatesOnlyNewIdentityBeforeLocalWrites(){
        remoteCreated();doThrow(new IllegalStateException("injected role failure")).when(identity).assignRealmRole(any(),eq("TEACHER"));
        assertThrows(IllegalStateException.class,()->service.createTeacher(request()));verify(identity).deleteUserQuietly(provisioned);verify(users,never()).saveAndFlush(any());verifyNoInteractions(manager);
    }
    @Test void localFailureRollsBackAndCompensatesRemoteIdentity(){
        remoteCreated();transaction();when(users.saveAndFlush(any())).thenAnswer(i->i.getArgument(0));
        when(teachers.saveAndFlush(any())).thenThrow(new DataIntegrityViolationException("synthetic duplicate"));
        assertThrows(DataIntegrityViolationException.class,()->service.createTeacher(request()));verify(manager).rollback(any());verify(manager,never()).commit(any());verify(identity).deleteUserQuietly(provisioned);
    }
    @Test void duplicateUsernameRejectedBeforeIdentityMutation(){
        when(users.existsByUsernameIgnoreCase("qa.teacher")).thenReturn(true);
        assertThrows(WebException.class,()->service.createTeacher(request()));verifyNoInteractions(identity,manager);
    }
    @Test void duplicateEmailRejectedBeforeIdentityMutation(){
        when(users.existsByEmailIgnoreCase("teacher@qa.invalid")).thenReturn(true);
        assertThrows(WebException.class,()->service.createTeacher(request()));verifyNoInteractions(identity,manager);
    }
    @Test void duplicateTeacherCodeRejectedBeforeIdentityMutation(){
        when(teachers.existsByTeacherCodeIgnoreCase("T-QA")).thenReturn(true);
        assertThrows(WebException.class,()->service.createTeacher(request()));verifyNoInteractions(identity,manager);
    }
}
