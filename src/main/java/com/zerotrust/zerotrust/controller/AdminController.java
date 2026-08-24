package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.model.request.CreateStudentRequestDTO;
import com.zerotrust.zerotrust.model.request.CreateStudentClassRequestDTO;
import com.zerotrust.zerotrust.model.response.ApiResponse;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.StudentClassResponseDTO;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;
import com.zerotrust.zerotrust.service.StudentAdministrationService;
import com.zerotrust.zerotrust.service.StudentClassAdministrationService;
import com.zerotrust.zerotrust.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    private final StudentAdministrationService studentAdministrationService;
    private final StudentClassAdministrationService studentClassAdministrationService;
    private final UserService userService;

    @PostMapping("/student-classes")
    public ResponseEntity<ApiResponse<StudentClassResponseDTO>> createStudentClass(
            @Valid @RequestBody CreateStudentClassRequestDTO request) {
        StudentClassResponseDTO studentClass =
                studentClassAdministrationService.createStudentClass(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(studentClass, "Student class created successfully"));
    }

    @GetMapping("/student-classes")
    public ResponseEntity<ApiResponse<PageResponse<StudentClassResponseDTO>>> getStudentClasses(
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) String department,
            @RequestParam(required = false) String academicYear,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "classCode,asc") String sort) {
        PageResponse<StudentClassResponseDTO> studentClasses =
                studentClassAdministrationService.getStudentClasses(
                        keyword,
                        department,
                        academicYear,
                        page,
                        size,
                        sort);
        return ResponseEntity.ok(
                ApiResponse.success(studentClasses, "Fetched student classes successfully"));
    }

    @PostMapping("/students")
    public ResponseEntity<ApiResponse<StudentResponseDTO>> createStudent(
            @Valid @RequestBody CreateStudentRequestDTO request) {
        StudentResponseDTO student = studentAdministrationService.createStudent(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(student, "Student account created successfully"));
    }

    @GetMapping("/users")
    public ResponseEntity<ApiResponse<List<UserResponseDTO>>> getAllUsers() {
        return ResponseEntity.ok(
                ApiResponse.success(userService.getAllUsers(), "Fetched all users successfully"));
    }
}
