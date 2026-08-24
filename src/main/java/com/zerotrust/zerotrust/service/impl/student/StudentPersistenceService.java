package com.zerotrust.zerotrust.service.impl.student;

import com.zerotrust.zerotrust.converter.StudentConverter;
import com.zerotrust.zerotrust.entity.StudentClassEntity;
import com.zerotrust.zerotrust.entity.StudentEntity;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.CreateStudentRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateStudentRequestDTO;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import com.zerotrust.zerotrust.repository.StudentClassRepository;
import com.zerotrust.zerotrust.repository.StudentRepository;
import com.zerotrust.zerotrust.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class StudentPersistenceService {
    private final UserRepository userRepository;
    private final StudentRepository studentRepository;
    private final StudentClassRepository studentClassRepository;
    private final StudentConverter studentConverter;

    @Transactional
    public StudentResponseDTO saveStudent(
            UUID keycloakUserId,
            CreateStudentRequestDTO request) {
        StudentClassEntity studentClass = studentClassRepository
                .findByClassCodeIgnoreCase(request.getClassCode().trim())
                .orElseThrow(() -> new WebException(ErrorCode.STUDENT_CLASS_NOT_FOUND));

        UserEntity user = new UserEntity();
        user.setKeycloakUserId(keycloakUserId);
        user.setUsername(request.getUsername().trim());
        user.setEmail(request.getEmail().trim().toLowerCase(Locale.ROOT));
        user.setFirstName(request.getFirstName().trim());
        user.setLastName(request.getLastName().trim());
        user.setStatus(UserEntity.Status.ACTIVE);
        UserEntity savedUser = userRepository.saveAndFlush(user);

        StudentEntity student = new StudentEntity();
        student.setUserEntity(savedUser);
        student.setStudentCode(request.getStudentCode().trim().toUpperCase(Locale.ROOT));
        student.setDateOfBirth(request.getDateOfBirth());
        student.setGender(request.getGender().trim().toUpperCase(Locale.ROOT));
        student.setPhone(normalizeOptional(request.getPhone()));
        student.setAddress(normalizeOptional(request.getAddress()));
        student.setStudentClassEntity(studentClass);
        StudentEntity savedStudent = studentRepository.saveAndFlush(student);

        return studentConverter.convertToDto(savedStudent);
    }

    @Transactional
    public StudentResponseDTO updateStudent(
            UUID studentId,
            UpdateStudentRequestDTO request) {
        StudentEntity student = studentRepository.findDetailedById(studentId)
                .orElseThrow(() -> new WebException(ErrorCode.STUDENT_NOT_FOUND));
        UserEntity user = student.getUserEntity();

        if (request.getFirstName() != null) {
            user.setFirstName(request.getFirstName().trim());
        }
        if (request.getLastName() != null) {
            user.setLastName(request.getLastName().trim());
        }
        if (request.getEmail() != null) {
            user.setEmail(request.getEmail().trim().toLowerCase(Locale.ROOT));
        }
        if (request.getStudentCode() != null) {
            student.setStudentCode(request.getStudentCode().trim().toUpperCase(Locale.ROOT));
        }
        if (request.getDateOfBirth() != null) {
            student.setDateOfBirth(request.getDateOfBirth());
        }
        if (request.getGender() != null) {
            student.setGender(request.getGender().trim().toUpperCase(Locale.ROOT));
        }
        if (request.getPhone() != null) {
            student.setPhone(normalizeOptional(request.getPhone()));
        }
        if (request.getAddress() != null) {
            student.setAddress(normalizeOptional(request.getAddress()));
        }
        if (request.getClassCode() != null) {
            StudentClassEntity studentClass = studentClassRepository
                    .findByClassCodeIgnoreCase(request.getClassCode().trim())
                    .orElseThrow(() -> new WebException(ErrorCode.STUDENT_CLASS_NOT_FOUND));
            student.setStudentClassEntity(studentClass);
        }

        StudentEntity savedStudent = studentRepository.saveAndFlush(student);
        return studentConverter.convertToDto(savedStudent);
    }

    private String normalizeOptional(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}
