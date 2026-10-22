package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.ScheduleEntryEntity;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.domain.Pageable;
import java.util.*;

public interface ScheduleEntryRepository extends JpaRepository<ScheduleEntryEntity, UUID> {
    @EntityGraph(attributePaths = {"assignmentEntity.teacherEntity.userEntity", "assignmentEntity.studentClassEntity", "assignmentEntity.subjectEntity"})
    List<ScheduleEntryEntity> findByAssignmentEntityStudentClassEntityIdOrderByWeekdayAscStartTimeAsc(UUID id, Pageable pageable);
    @EntityGraph(attributePaths = {"assignmentEntity.teacherEntity.userEntity", "assignmentEntity.studentClassEntity", "assignmentEntity.subjectEntity"})
    List<ScheduleEntryEntity> findByAssignmentEntityTeacherEntityIdOrderByWeekdayAscStartTimeAsc(UUID id, Pageable pageable);
}
