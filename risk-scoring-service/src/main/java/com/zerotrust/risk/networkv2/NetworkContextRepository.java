package com.zerotrust.risk.networkv2;

import jakarta.persistence.QueryHint;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface NetworkContextRepository extends JpaRepository<NetworkAuthenticationContextEntity, String> {
    @Query("""
            SELECT n FROM NetworkAuthenticationContextEntity n
            WHERE n.subjectHash = :subject AND n.clientId = :client
              AND n.authenticatedAt >= :start AND n.authenticatedAt < :now
              AND n.recordedAt <= :now ORDER BY n.authenticatedAt DESC
            """)
    @QueryHints(@QueryHint(name = "jakarta.persistence.query.timeout", value = "2000"))
    List<NetworkAuthenticationContextEntity> recent(@Param("subject") String subjectHash,
            @Param("client") String clientId, @Param("start") Instant start,
            @Param("now") Instant now, Pageable page);
}
