package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.model.academic.TeachingRequests;
import com.zerotrust.zerotrust.model.response.*;
import com.zerotrust.zerotrust.service.impl.TeachingAdministrationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;
import java.sql.SQLException;
import java.util.*;

@RestController @RequestMapping("/api/admin") @RequiredArgsConstructor @PreAuthorize("hasRole('ADMIN')")
public class AdminTeachingController {
    private final TeachingAdministrationService service;
    @GetMapping("/teachers") public ApiResponse<?> teachers() { return ApiResponse.success(service.teachers(),"Teachers"); }
    @PostMapping("/teachers") public ResponseEntity<?> createTeacher(@Valid @RequestBody TeachingRequests.TeacherCreate r) { return ResponseEntity.status(201).body(ApiResponse.success(service.createTeacher(r),"Teacher created")); }
    @PutMapping("/teachers/{id}") public ApiResponse<?> updateTeacher(@PathVariable UUID id,@Valid @RequestBody TeachingRequests.TeacherUpdate r) { return ApiResponse.success(service.updateTeacher(id,r),"Teacher updated"); }
    @GetMapping("/teaching-assignments") public ApiResponse<?> assignments() { return ApiResponse.success(service.assignments(),"Assignments"); }
    @PostMapping("/teaching-assignments") public ResponseEntity<?> createAssignment(@Valid @RequestBody TeachingRequests.Assignment r) { return ResponseEntity.status(201).body(ApiResponse.success(service.createAssignment(r),"Assignment created")); }
    @PutMapping("/teaching-assignments/{id}") public ApiResponse<?> updateAssignment(@PathVariable UUID id,@Valid @RequestBody TeachingRequests.Assignment r) { return ApiResponse.success(service.updateAssignment(id,r),"Assignment updated"); }
    @DeleteMapping("/teaching-assignments/{id}") public ResponseEntity<Void> deleteAssignment(@PathVariable UUID id) { service.deleteAssignment(id);return ResponseEntity.noContent().build(); }
    @GetMapping("/schedules") public ApiResponse<?> schedules() { return ApiResponse.success(service.schedules(),"Schedules"); }
    @PostMapping("/schedules") public ResponseEntity<?> createSchedule(@Valid @RequestBody TeachingRequests.Schedule r) { return ResponseEntity.status(201).body(ApiResponse.success(service.createSchedule(r),"Schedule created")); }
    @PutMapping("/schedules/{id}") public ApiResponse<?> updateSchedule(@PathVariable UUID id,@Valid @RequestBody TeachingRequests.Schedule r) { return ApiResponse.success(service.updateSchedule(id,r),"Schedule updated"); }
    @DeleteMapping("/schedules/{id}") public ResponseEntity<Void> deleteSchedule(@PathVariable UUID id) { service.deleteSchedule(id);return ResponseEntity.noContent().build(); }

    /** New teaching FKs also protect catalogs managed by the original controller. */
    @RestControllerAdvice(assignableTypes = {AdminController.class,AdminTeachingController.class})
    public static class TeachingConstraints {
        @ExceptionHandler(DataIntegrityViolationException.class)
        public ResponseEntity<ApiErrorResponse> integrity(DataIntegrityViolationException error,HttpServletRequest request) {
            Throwable cause=error;String constraint="";boolean unnamedAssignmentReference=false;
            while (cause!=null) {
                if (cause instanceof org.hibernate.exception.ConstraintViolationException c) {
                    constraint=Objects.toString(c.getConstraintName(),"").toLowerCase(Locale.ROOT);
                    unnamedAssignmentReference|=isUnnamedAssignmentReference(c,request);
                }
                cause=cause.getCause();
            }
            boolean teaching=List.of("fk_teachers_user","fk_assignments_teacher","fk_assignments_class","fk_assignments_subject","fk_schedule_assignment","uk_assignment_teacher_class_subject")
                    .stream().anyMatch(constraint::contains);
            if (!teaching && !unnamedAssignmentReference) throw error;
            return ResponseEntity.status(409).body(ApiErrorResponse.builder().status(409).error("TEACHING_RESOURCE_CONFLICT")
                    .message("Teaching resource is referenced or assignment already exists").path(request.getRequestURI()).build());
        }
        private boolean isUnnamedAssignmentReference(org.hibernate.exception.ConstraintViolationException violation,HttpServletRequest request) {
            // MySQL may omit the constraint name for this FK rejection. Keep the
            // fallback bound to the recorded parent-delete statement and route.
            SQLException sql=violation.getSQLException();
            String statement=Objects.toString(violation.getSQL(),"").strip().replaceAll("\\s+"," ").toLowerCase(Locale.ROOT);
            return (violation.getConstraintName()==null || violation.getConstraintName().isBlank())
                    && sql!=null && "23000".equals(sql.getSQLState()) && (sql.getErrorCode()==1217 || sql.getErrorCode()==1451)
                    && "delete from teaching_assignments where id=?".equals(statement)
                    && "DELETE".equals(request.getMethod())
                    && request.getRequestURI().matches("/api/admin/teaching-assignments/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
        }
    }
}
