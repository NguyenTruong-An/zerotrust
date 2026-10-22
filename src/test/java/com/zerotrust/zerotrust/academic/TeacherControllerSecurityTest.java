package com.zerotrust.zerotrust.academic;

import com.zerotrust.zerotrust.config.SecurityConfig;
import com.zerotrust.zerotrust.controller.*;
import com.zerotrust.zerotrust.exception.*;
import com.zerotrust.zerotrust.security.KeycloakJwtAuthenticationConverter;
import com.zerotrust.zerotrust.service.impl.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.mock.web.MockHttpServletRequest;
import java.sql.SQLException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import java.util.*;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest({TeacherController.class,AdminTeachingController.class})
@Import({SecurityConfig.class,CustomAuthenticationEntryPoint.class,CustomAccessDeniedHandler.class,KeycloakJwtAuthenticationConverter.class})
class TeacherControllerSecurityTest {
    @Autowired MockMvc mvc;
    @MockitoBean TeacherAcademicService teacher;
    @MockitoBean TeachingAdministrationService admin;
    @MockitoBean JwtDecoder decoder;
    private DataIntegrityViolationException nativeFailure(int code,String state,String sql,String constraint) {
        return new DataIntegrityViolationException("Synthetic native constraint",new org.hibernate.exception.ConstraintViolationException(
                "Cannot delete or update a parent row: a foreign key constraint fails",new SQLException("Synthetic native FK",state,code),sql,constraint));
    }
    @ParameterizedTest @ValueSource(ints={1217,1451})
    void unnamedNativeAssignmentFkConflictReturns409(int code) throws Exception {
        UUID id=UUID.randomUUID();doThrow(nativeFailure(code,"23000","delete from teaching_assignments where id=?",null)).when(admin).deleteAssignment(id);
        mvc.perform(delete("/api/admin/teaching-assignments/"+id).with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error").value("TEACHING_RESOURCE_CONFLICT"));
        verify(admin).deleteAssignment(id);verifyNoMoreInteractions(admin);
    }
    @Test void unreferencedAssignmentDeleteRemains204() throws Exception {
        UUID id=UUID.randomUUID();mvc.perform(delete("/api/admin/teaching-assignments/"+id).with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isNoContent());verify(admin).deleteAssignment(id);verifyNoMoreInteractions(admin);
    }
    @Test void unexpectedSqlFailureIsNotTranslatedTo409() {
        UUID id=UUID.randomUUID();var failure=new DataIntegrityViolationException("Synthetic connection failure",new SQLException("Synthetic offline failure","08006",0));doThrow(failure).when(admin).deleteAssignment(id);
        var propagated=assertThrows(jakarta.servlet.ServletException.class,()->mvc.perform(delete("/api/admin/teaching-assignments/"+id).with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))));
        assertSame(failure,propagated.getCause());verify(admin).deleteAssignment(id);verifyNoMoreInteractions(admin);
    }
    @Test void unnamedFkFallbackRejectsUnrelatedDatabaseErrorsAndRoutes() {
        var advice=new AdminTeachingController.TeachingConstraints();String path="/api/admin/teaching-assignments/"+UUID.randomUUID();
        for (var failure:List.of(nativeFailure(1062,"23000","delete from teaching_assignments where id=?",null),
                nativeFailure(1452,"23000","delete from teaching_assignments where id=?",null),
                nativeFailure(1217,"42000","delete from teaching_assignments where id=?",null),
                nativeFailure(1217,"23000","delete from users where id=?",null),
                nativeFailure(1217,"23000",null,null),
                nativeFailure(1217,"23000","delete from teaching_assignments where id=?","unknown_fk"))) {
            assertSame(failure,assertThrows(DataIntegrityViolationException.class,()->advice.integrity(failure,new MockHttpServletRequest("DELETE",path))));
        }
        var failure=nativeFailure(1217,"23000","delete from teaching_assignments where id=?",null);
        for (var request:List.of(new MockHttpServletRequest("POST",path),new MockHttpServletRequest("DELETE","/api/admin/teachers/"+UUID.randomUUID()),new MockHttpServletRequest("DELETE",path+"/extra")))
            assertSame(failure,assertThrows(DataIntegrityViolationException.class,()->advice.integrity(failure,request)));
    }
    @Test void unauthenticatedTeacherApiIs401() throws Exception {mvc.perform(get("/api/teachers/me")).andExpect(status().isUnauthorized());verifyNoInteractions(teacher);}
    @Test void studentCannotUseTeacherOrAdminApi() throws Exception {
        var auth=jwt().authorities(new SimpleGrantedAuthority("ROLE_STUDENT"));
        mvc.perform(get("/api/teachers/me").with(auth)).andExpect(status().isForbidden());
        mvc.perform(get("/api/admin/teachers").with(auth)).andExpect(status().isForbidden());verifyNoInteractions(teacher,admin);
    }
    @Test void teacherCannotUseAdminTeachingApi() throws Exception {
        mvc.perform(get("/api/admin/teachers").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_TEACHER")))).andExpect(status().isForbidden());verifyNoInteractions(admin);
    }
    @Test void subjectIsTakenFromJwtNotHeadersOrQuery() throws Exception {
        UUID subject=UUID.randomUUID();when(teacher.assignments(subject)).thenReturn(List.of());
        mvc.perform(get("/api/teachers/me/assignments?subjectId="+UUID.randomUUID()).header("X-Subject",UUID.randomUUID().toString())
                .with(jwt().jwt(j->j.subject(subject.toString())).authorities(new SimpleGrantedAuthority("ROLE_TEACHER"))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data").isArray());verify(teacher).assignments(subject);
    }
    @Test void malformedSubjectIs401AndDoesNotCallService() throws Exception {
        mvc.perform(get("/api/teachers/me").with(jwt().jwt(j->j.subject("not-a-uuid")).authorities(new SimpleGrantedAuthority("ROLE_TEACHER"))))
                .andExpect(status().isUnauthorized());verifyNoInteractions(teacher);
    }
    @Test void gradeIdentityOverrideAndInvalidGradeAre400() throws Exception {
        String uri="/api/teachers/assignments/"+UUID.randomUUID()+"/students/"+UUID.randomUUID()+"/score";
        var auth=jwt().jwt(j->j.subject(UUID.randomUUID().toString())).authorities(new SimpleGrantedAuthority("ROLE_TEACHER"));
        mvc.perform(patch(uri).with(auth).contentType("application/json").content("{\"attendanceScore\":8,\"subjectId\":\"forged\"}" )).andExpect(status().isBadRequest());
        mvc.perform(patch(uri).with(auth).contentType("application/json").content("{\"attendanceScore\":11}" )).andExpect(status().isBadRequest());verifyNoInteractions(teacher);
    }
}
