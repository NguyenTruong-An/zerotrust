package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.StudentClassEntity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class StudentClassRepositoryTest {
    @Autowired
    private StudentClassRepository studentClassRepository;

    @Test
    void filtersStudentClassesCaseInsensitivelyAndAppliesPaging() {
        studentClassRepository.saveAllAndFlush(List.of(
                studentClass(
                        "AT19A",
                        "An toan thong tin 19A",
                        "An toan thong tin",
                        "2022-2026"),
                studentClass(
                        "AT19B",
                        "An toan thong tin 19B",
                        "An toan thong tin",
                        "2022-2026"),
                studentClass(
                        "CNTT01",
                        "Cong nghe thong tin 01",
                        "Cong nghe thong tin",
                        "2023-2027")));

        var result = studentClassRepository.findAllFiltered(
                "at19",
                "AN TOAN THONG TIN",
                "2022-2026",
                PageRequest.of(0, 1, Sort.by(Sort.Direction.DESC, "classCode")));

        assertThat(result.getTotalElements()).isEqualTo(2);
        assertThat(result.getTotalPages()).isEqualTo(2);
        assertThat(result.getContent())
                .extracting(StudentClassEntity::getClassCode)
                .containsExactly("AT19B");
    }

    private StudentClassEntity studentClass(
            String classCode,
            String className,
            String department,
            String academicYear) {
        StudentClassEntity studentClass = new StudentClassEntity();
        studentClass.setClassCode(classCode);
        studentClass.setClassName(className);
        studentClass.setDepartment(department);
        studentClass.setAcademicYear(academicYear);
        return studentClass;
    }
}
