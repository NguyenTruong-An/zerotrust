package com.zerotrust.risk.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Objects;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(
        name = "authentication_success_events",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_authentication_success_events_event_id",
                columnNames = "event_id"
        )
)
public class AuthenticationSuccessEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_id", nullable = false, length = 255)
    private String eventId;

    @Column(name = "subject_id", nullable = false, length = 255)
    private String subjectId;

    @Column(name = "client_id", nullable = false, length = 255)
    private String clientId;

    @Column(name = "authenticated_at", nullable = false, columnDefinition = "TIMESTAMP(6)")
    private Instant authenticatedAt;

    @Column(name = "recorded_at", nullable = false, columnDefinition = "TIMESTAMP(6)")
    private Instant recordedAt;

    public AuthenticationSuccessEventEntity(
            String eventId,
            String subjectId,
            String clientId,
            Instant authenticatedAt,
            Instant recordedAt
    ) {
        this.eventId = requireText(eventId, "eventId");
        this.subjectId = requireText(subjectId, "subjectId");
        this.clientId = requireText(clientId, "clientId");
        this.authenticatedAt = Objects.requireNonNull(
                authenticatedAt,
                "authenticatedAt must not be null"
        );
        this.recordedAt = Objects.requireNonNull(recordedAt, "recordedAt must not be null");
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value.trim();
    }
}
