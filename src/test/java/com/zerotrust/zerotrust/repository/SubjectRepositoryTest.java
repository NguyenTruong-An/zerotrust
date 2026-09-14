package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.SubjectEntity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest(showSql = false)
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class SubjectRepositoryTest {
    @Autowired
    private SubjectRepository subjectRepository;

    @Test
    void filtersSubjectsByCodeOrNameAndAppliesPagination() {
        subjectRepository.saveAllAndFlush(List.of(
                subject("SEC101", "Nhap mon an toan thong tin", 3),
                subject("SEC201", "An toan mang", 4),
                subject("DB101", "Co so du lieu", 3)));

        var result = subjectRepository.findAllFiltered(
                "sec",
                PageRequest.of(
                        0,
                        1,
                        Sort.by(Sort.Direction.DESC, "subjectCode")));

        assertThat(result.getTotalElements()).isEqualTo(2);
        assertThat(result.getTotalPages()).isEqualTo(2);
        assertThat(result.getContent())
                .extracting(SubjectEntity::getSubjectCode)
                .containsExactly("SEC201");
        assertThat(subjectRepository.existsBySubjectNameIgnoreCase("AN TOAN MANG")).isTrue();
    }

    @Test
    void rejectsDuplicateSubjectNameWithAnotherCode() {
        subjectRepository.saveAndFlush(subject("SEC101", "An toan mang", 3));

        assertThatThrownBy(() -> subjectRepository.saveAndFlush(
                subject("SEC102", "An toan mang", 4)))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    private SubjectEntity subject(String code, String name, int credits) {
        SubjectEntity subject = new SubjectEntity();
        subject.setSubjectCode(code);
        subject.setSubjectName(name);
        subject.setCredits((short) credits);
        return subject;
    }
}
