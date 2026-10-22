package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.exception.*;
import com.zerotrust.zerotrust.model.academic.*;
import com.zerotrust.zerotrust.model.response.ApiResponse;
import com.zerotrust.zerotrust.service.impl.TeacherAcademicService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController @RequestMapping("/api/teachers") @RequiredArgsConstructor
@PreAuthorize("hasRole('TEACHER')")
public class TeacherController {
    private final TeacherAcademicService service;
    @GetMapping("/me") public ApiResponse<?> me(@AuthenticationPrincipal Jwt jwt) { return ApiResponse.success(service.me(subject(jwt)),"Teacher profile"); }
    @GetMapping("/me/assignments") public ApiResponse<?> assignments(@AuthenticationPrincipal Jwt jwt) { return ApiResponse.success(service.assignments(subject(jwt)),"Teaching assignments"); }
    @GetMapping("/me/schedule") public ApiResponse<?> schedule(@AuthenticationPrincipal Jwt jwt) { return ApiResponse.success(service.schedule(subject(jwt)),"Teaching schedule"); }
    @GetMapping("/assignments/{id}/students") public ApiResponse<?> roster(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id) { return ApiResponse.success(service.roster(subject(jwt),id),"Assigned class roster"); }
    @PatchMapping("/assignments/{id}/students/{studentId}/score")
    public ApiResponse<?> grade(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@PathVariable UUID studentId,@Valid @RequestBody TeachingRequests.Grade request) {
        return ApiResponse.success(service.grade(subject(jwt),id,studentId,request),"Grade saved");
    }
    static UUID subject(Jwt jwt) {
        try { return UUID.fromString(jwt.getSubject()); }
        catch (IllegalArgumentException | NullPointerException e) { throw new WebException(ErrorCode.UNAUTHORIZED); }
    }
}
