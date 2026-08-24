package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.SubjectEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.CreateSubjectRequestDTO;
import com.zerotrust.zerotrust.repository.SubjectRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SubjectAdministrationServiceImplTest {
    @Mock
    private SubjectRepository subjectRepository;

    private SubjectAdministrationServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new SubjectAdministrationServiceImpl(subjectRepository);
    }

    @Test
    void createsNormalizedSubject() {
        CreateSubjectRequestDTO request = request(" sec101 ");
        request.setSubjectName(" Nhap mon an toan thong tin ");
        request.setDescription("   ");
        when(subjectRepository.saveAndFlush(any(SubjectEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        var response = service.createSubject(request);

        ArgumentCaptor<SubjectEntity> entityCaptor =
                ArgumentCaptor.forClass(SubjectEntity.class);
        verify(subjectRepository).existsBySubjectCodeIgnoreCase("SEC101");
        verify(subjectRepository).saveAndFlush(entityCaptor.capture());
        assertThat(entityCaptor.getValue().getSubjectCode()).isEqualTo("SEC101");
        assertThat(entityCaptor.getValue().getSubjectName())
                .isEqualTo("Nhap mon an toan thong tin");
        assertThat(entityCaptor.getValue().getDescription()).isNull();
        assertThat(response.subjectCode()).isEqualTo("SEC101");
        assertThat(response.credits()).isEqualTo((short) 3);
    }

    @Test
    void rejectsDuplicateSubjectCode() {
        CreateSubjectRequestDTO request = request("SEC101");
        when(subjectRepository.existsBySubjectCodeIgnoreCase("SEC101")).thenReturn(true);

        assertThatThrownBy(() -> service.createSubject(request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.SUBJECT_CODE_EXISTS);
        verify(subjectRepository, never()).saveAndFlush(any());
    }

    @Test
    void translatesConcurrentDuplicateIntoSubjectCodeError() {
        CreateSubjectRequestDTO request = request("SEC101");
        when(subjectRepository.saveAndFlush(any(SubjectEntity.class)))
                .thenThrow(new DataIntegrityViolationException("duplicate subject code"));

        assertThatThrownBy(() -> service.createSubject(request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.SUBJECT_CODE_EXISTS);
    }

    @Test
    void returnsFilteredPaginatedSubjects() {
        SubjectEntity subject = new SubjectEntity();
        UUID id = UUID.randomUUID();
        subject.setId(id);
        subject.setSubjectCode("SEC101");
        subject.setSubjectName("Nhap mon an toan thong tin");
        subject.setCredits((short) 3);
        when(subjectRepository.findAllFiltered(any(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(subject)));

        var response = service.getSubjects(" SEC ", 0, 10, "credits,desc");

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(subjectRepository).findAllFiltered(
                org.mockito.ArgumentMatchers.eq("SEC"),
                pageableCaptor.capture());
        assertThat(pageableCaptor.getValue().getPageNumber()).isZero();
        assertThat(pageableCaptor.getValue().getPageSize()).isEqualTo(10);
        assertThat(pageableCaptor.getValue().getSort().getOrderFor("credits"))
                .extracting(Sort.Order::getDirection)
                .isEqualTo(Sort.Direction.DESC);
        assertThat(response.content()).singleElement().satisfies(result -> {
            assertThat(result.id()).isEqualTo(id);
            assertThat(result.subjectCode()).isEqualTo("SEC101");
        });
    }

    @Test
    void rejectsInvalidPaginationAndSort() {
        assertThatThrownBy(() -> service.getSubjects(null, -1, 20, "subjectCode,asc"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        assertThatThrownBy(() -> service.getSubjects(null, 0, 101, "subjectCode,asc"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        assertThatThrownBy(() -> service.getSubjects(null, 0, 20, "createdAt,desc"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);

        verify(subjectRepository, never()).findAllFiltered(any(), any());
    }

    private CreateSubjectRequestDTO request(String subjectCode) {
        return CreateSubjectRequestDTO.builder()
                .subjectCode(subjectCode)
                .subjectName("Nhap mon an toan thong tin")
                .credits((short) 3)
                .description("Kien thuc co ban")
                .build();
    }
}
