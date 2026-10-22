package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.*;
import com.zerotrust.zerotrust.model.academic.TeachingResponses;
import com.zerotrust.zerotrust.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.*;

@Service @RequiredArgsConstructor
public class StudentScheduleService {
    private final StudentRepository students;
    private final ScheduleEntryRepository schedules;
    @PreAuthorize("hasRole('STUDENT')")
    @Transactional(readOnly = true)
    public List<TeachingResponses.Schedule> current(UUID subject) {
        var student=students.findByUserEntityKeycloakUserId(subject).orElseThrow(() -> new WebException(ErrorCode.STUDENT_NOT_FOUND));
        if (student.getUserEntity().getStatus()!=UserEntity.Status.ACTIVE) throw new WebException(ErrorCode.USER_INACTIVE);
        return schedules.findByAssignmentEntityStudentClassEntityIdOrderByWeekdayAscStartTimeAsc(
                student.getStudentClassEntity().getId(),PageRequest.of(0,200)).stream().map(TeachingResponses::schedule).toList();
    }
}
