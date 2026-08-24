package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.StudentClassEntity;
import com.zerotrust.zerotrust.entity.StudentEntity;
import com.zerotrust.zerotrust.entity.UserEntity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest(showSql = false)
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class StudentRepositoryTest {
    @Autowired
    private StudentRepository studentRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private StudentClassRepository studentClassRepository;
    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void filtersStudentsAndLoadsTheirUserAndClassDetails() {
        StudentClassEntity studentClass = studentClassRepository.saveAndFlush(studentClass());
        UserEntity firstUser = userRepository.saveAndFlush(user(
                "student01", UserEntity.Status.ACTIVE));
        UserEntity secondUser = userRepository.saveAndFlush(user(
                "student02", UserEntity.Status.ACTIVE));
        UserEntity inactiveUser = userRepository.saveAndFlush(user(
                "student03", UserEntity.Status.INACTIVE));
        StudentEntity firstStudent = student("SV001", firstUser, studentClass);
        StudentEntity secondStudent = student("SV002", secondUser, studentClass);
        StudentEntity inactiveStudent = student("SV003", inactiveUser, studentClass);
        studentRepository.saveAllAndFlush(List.of(
                firstStudent,
                secondStudent,
                inactiveStudent));
        UUID firstStudentId = firstStudent.getId();
        entityManager.clear();

        var result = studentRepository.findAllFiltered(
                "STUDENT",
                "at19b",
                UserEntity.Status.ACTIVE,
                PageRequest.of(
                        0,
                        1,
                        Sort.by(Sort.Direction.DESC, "userEntity.username")));

        assertThat(result.getTotalElements()).isEqualTo(2);
        assertThat(result.getTotalPages()).isEqualTo(2);
        assertThat(result.getContent())
                .extracting(student -> student.getUserEntity().getUsername())
                .containsExactly("student02");
        assertThat(entityManager.getEntityManagerFactory()
                        .getPersistenceUnitUtil()
                        .isLoaded(result.getContent().get(0).getUserEntity()))
                .isTrue();
        assertThat(entityManager.getEntityManagerFactory()
                        .getPersistenceUnitUtil()
                        .isLoaded(result.getContent().get(0).getStudentClassEntity()))
                .isTrue();

        var detailedStudent = studentRepository.findDetailedById(firstStudentId).orElseThrow();
        assertThat(detailedStudent.getUserEntity().getUsername()).isEqualTo("student01");
        assertThat(detailedStudent.getStudentClassEntity().getClassCode()).isEqualTo("AT19B");
    }

    private UserEntity user(String username, UserEntity.Status status) {
        UserEntity user = new UserEntity();
        user.setKeycloakUserId(UUID.randomUUID());
        user.setUsername(username);
        user.setEmail(username + "@example.com");
        user.setFirstName("An");
        user.setLastName("Nguyen");
        user.setStatus(status);
        return user;
    }

    private StudentClassEntity studentClass() {
        StudentClassEntity studentClass = new StudentClassEntity();
        studentClass.setClassCode("AT19B");
        studentClass.setClassName("An toan thong tin 19B");
        studentClass.setDepartment("An toan thong tin");
        studentClass.setAcademicYear("2022-2026");
        return studentClass;
    }

    private StudentEntity student(
            String studentCode,
            UserEntity user,
            StudentClassEntity studentClass) {
        StudentEntity student = new StudentEntity();
        student.setUserEntity(user);
        student.setStudentClassEntity(studentClass);
        student.setStudentCode(studentCode);
        student.setDateOfBirth(LocalDate.of(2003, 5, 20));
        student.setGender("MALE");
        return student;
    }
}
