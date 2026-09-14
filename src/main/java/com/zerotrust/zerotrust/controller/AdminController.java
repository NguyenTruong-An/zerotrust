package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.model.request.CreateStudentRequestDTO;
import com.zerotrust.zerotrust.model.request.CreateStudentClassRequestDTO;
import com.zerotrust.zerotrust.model.request.CreateScoreRequestDTO;
import com.zerotrust.zerotrust.model.request.CreateSubjectRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateStudentRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateScoreRequestDTO;
import com.zerotrust.zerotrust.model.request.UpsertSubjectScoresRequestDTO;
import com.zerotrust.zerotrust.model.response.ApiResponse;
import com.zerotrust.zerotrust.model.response.BatchScoreResponseDTO;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.ScoreResponseDTO;
import com.zerotrust.zerotrust.model.response.StudentClassResponseDTO;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import com.zerotrust.zerotrust.model.response.SubjectResponseDTO;
import com.zerotrust.zerotrust.model.response.SubjectScoreSheetRowResponseDTO;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;
import com.zerotrust.zerotrust.service.StudentAdministrationService;
import com.zerotrust.zerotrust.service.ScoreAdministrationService;
import com.zerotrust.zerotrust.service.StudentClassAdministrationService;
import com.zerotrust.zerotrust.service.SubjectAdministrationService;
import com.zerotrust.zerotrust.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    private final ScoreAdministrationService scoreAdministrationService;
    private final StudentAdministrationService studentAdministrationService;
    private final StudentClassAdministrationService studentClassAdministrationService;
    private final SubjectAdministrationService subjectAdministrationService;
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
            @RequestParam(required = false) String courseYears,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "classCode,asc") String sort) {
        PageResponse<StudentClassResponseDTO> studentClasses =
                studentClassAdministrationService.getStudentClasses(
                        keyword,
                        department,
                        courseYears,
                        page,
                        size,
                        sort);
        return ResponseEntity.ok(
                ApiResponse.success(studentClasses, "Fetched student classes successfully"));
    }

    @DeleteMapping("/student-classes/{classId}")
    public ResponseEntity<Void> deleteStudentClass(@PathVariable UUID classId) {
        studentClassAdministrationService.deleteStudentClass(classId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/subjects")
    public ResponseEntity<ApiResponse<SubjectResponseDTO>> createSubject(
            @Valid @RequestBody CreateSubjectRequestDTO request) {
        SubjectResponseDTO subject = subjectAdministrationService.createSubject(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(subject, "Subject created successfully"));
    }

    @GetMapping("/subjects")
    public ResponseEntity<ApiResponse<PageResponse<SubjectResponseDTO>>> getSubjects(
            @RequestParam(required = false) String keyword,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "subjectCode,asc") String sort) {
        PageResponse<SubjectResponseDTO> subjects = subjectAdministrationService.getSubjects(
                keyword,
                page,
                size,
                sort);
        return ResponseEntity.ok(
                ApiResponse.success(subjects, "Fetched subjects successfully"));
    }

    @DeleteMapping("/subjects/{subjectId}")
    public ResponseEntity<Void> deleteSubject(@PathVariable UUID subjectId) {
        subjectAdministrationService.deleteSubject(subjectId);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/subjects/{subjectId}/score-sheet")
    public ResponseEntity<ApiResponse<PageResponse<SubjectScoreSheetRowResponseDTO>>>
            getSubjectScoreSheet(
                    @PathVariable UUID subjectId,
                    @RequestParam String classCode,
                    @RequestParam(required = false) String keyword,
                    @RequestParam(defaultValue = "0") int page,
                    @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(ApiResponse.success(
                scoreAdministrationService.getSubjectScoreSheet(
                        subjectId, classCode, keyword, page, size),
                "Fetched subject score sheet successfully"));
    }

    @PostMapping("/subjects/{subjectId}/scores/batch")
    public ResponseEntity<ApiResponse<BatchScoreResponseDTO>> upsertSubjectScores(
            @PathVariable UUID subjectId,
            @Valid @RequestBody UpsertSubjectScoresRequestDTO request) {
        return ResponseEntity.ok(ApiResponse.success(
                scoreAdministrationService.upsertSubjectScores(subjectId, request),
                "Saved subject scores successfully"));
    }

    @PostMapping("/students/{studentId}/scores")
    public ResponseEntity<ApiResponse<ScoreResponseDTO>> createStudentScore(
            @PathVariable UUID studentId,
            @Valid @RequestBody CreateScoreRequestDTO request) {
        ScoreResponseDTO score = scoreAdministrationService.createStudentScore(
                studentId,
                request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(score, "Student score created successfully"));
    }

    @GetMapping("/students/{studentId}/scores")
    public ResponseEntity<ApiResponse<PageResponse<ScoreResponseDTO>>> getStudentScores(
            @PathVariable UUID studentId,
            @RequestParam(required = false) UUID subjectId,
            @RequestParam(required = false) Short semester,
            @RequestParam(required = false) String academicYear,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "academicYear,desc") String sort) {
        PageResponse<ScoreResponseDTO> scores = scoreAdministrationService.getStudentScores(
                studentId,
                subjectId,
                semester,
                academicYear,
                page,
                size,
                sort);
        return ResponseEntity.ok(
                ApiResponse.success(scores, "Fetched student scores successfully"));
    }

    @PatchMapping("/scores/{scoreId}")
    public ResponseEntity<ApiResponse<ScoreResponseDTO>> updateScore(
            @PathVariable UUID scoreId,
            @Valid @RequestBody UpdateScoreRequestDTO request) {
        return ResponseEntity.ok(ApiResponse.success(
                scoreAdministrationService.updateScore(scoreId, request),
                "Student score updated successfully"));
    }

    @DeleteMapping("/scores/{scoreId}")
    public ResponseEntity<Void> deleteScore(@PathVariable UUID scoreId) {
        scoreAdministrationService.deleteScore(scoreId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/students")
    public ResponseEntity<ApiResponse<StudentResponseDTO>> createStudent(
            @Valid @RequestBody CreateStudentRequestDTO request) {
        StudentResponseDTO student = studentAdministrationService.createStudent(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(student, "Student account created successfully"));
    }

    @GetMapping("/students")
    public ResponseEntity<ApiResponse<PageResponse<StudentResponseDTO>>> getStudents(
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) String classCode,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "studentCode,asc") String sort) {
        PageResponse<StudentResponseDTO> students = studentAdministrationService.getStudents(
                keyword,
                classCode,
                status,
                page,
                size,
                sort);
        return ResponseEntity.ok(
                ApiResponse.success(students, "Fetched students successfully"));
    }

    @GetMapping("/students/{id}")
    public ResponseEntity<ApiResponse<StudentResponseDTO>> getStudent(
            @PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.success(
                studentAdministrationService.getStudent(id),
                "Fetched student successfully"));
    }

    @PatchMapping("/students/{id}")
    public ResponseEntity<ApiResponse<StudentResponseDTO>> updateStudent(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateStudentRequestDTO request) {
        return ResponseEntity.ok(ApiResponse.success(
                studentAdministrationService.updateStudent(id, request),
                "Updated student profile successfully"));
    }

    @GetMapping("/users")
    public ResponseEntity<ApiResponse<List<UserResponseDTO>>> getAllUsers() {
        return ResponseEntity.ok(
                ApiResponse.success(userService.getAllUsers(), "Fetched all users successfully"));
    }
}
