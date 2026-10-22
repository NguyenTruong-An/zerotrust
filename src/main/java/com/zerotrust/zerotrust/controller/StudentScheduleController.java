package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.model.response.ApiResponse;
import com.zerotrust.zerotrust.service.impl.StudentScheduleService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController @RequiredArgsConstructor @PreAuthorize("hasRole('STUDENT')")
public class StudentScheduleController {
    private final StudentScheduleService service;
    @GetMapping("/api/students/me/schedule")
    public ApiResponse<?> schedule(@AuthenticationPrincipal Jwt jwt) { return ApiResponse.success(service.current(TeacherController.subject(jwt)),"Student schedule"); }
}
