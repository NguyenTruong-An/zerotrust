package com.zerotrust.zerotrust.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.Check;
import java.time.LocalTime;
import java.util.UUID;

@Entity @Table(name = "schedule_entries")
@Check(constraints = "weekday BETWEEN 1 AND 7 AND start_time < end_time")
@Getter @Setter
public class ScheduleEntryEntity extends AuditableEntity {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "assignment_id", nullable = false, foreignKey = @ForeignKey(name = "fk_schedule_assignment"))
    private TeachingAssignmentEntity assignmentEntity;
    @Column(nullable = false) private int weekday;
    @Column(name = "start_time", nullable = false) private LocalTime startTime;
    @Column(name = "end_time", nullable = false) private LocalTime endTime;
    @Column(nullable = false, length = 80) private String room;
}
