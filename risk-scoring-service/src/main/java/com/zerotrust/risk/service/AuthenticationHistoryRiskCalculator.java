package com.zerotrust.risk.service;

import com.zerotrust.risk.config.AuthenticationHistoryRiskProperties;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.repository.AuthenticationFailureStore;
import lombok.RequiredArgsConstructor;
import org.jboss.logging.Logger;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.Objects;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationHistoryRiskCalculator {

    private static final Logger LOGGER = Logger.getLogger(AuthenticationHistoryRiskCalculator.class);

    private final AuthenticationFailureStore failureStore;
    private final AuthenticationHistoryRiskProperties properties;

    public Optional<BigDecimal> calculate(LoginContext context) {
        Objects.requireNonNull(context, "context must not be null");

        try {
            BigDecimal subjectRisk = scoreFor(
                    failureStore.countBySubject(context.subjectId()),
                    properties.getSubjectMediumMinimum(),
                    properties.getSubjectHighMinimum()
            );
            BigDecimal sourceIpRisk = scoreFor(
                    failureStore.countBySourceIp(context.ipAddress()),
                    properties.getSourceIpMediumMinimum(),
                    properties.getSourceIpHighMinimum()
            );

            // One failure normally contributes to both counters. Taking the maximum avoids
            // double-counting while retaining the stronger account or network signal.
            return Optional.of(subjectRisk.max(sourceIpRisk));
        } catch (DataAccessException exception) {
            LOGGER.warnf(
                    "Authentication-history Redis data is unavailable: reason=%s",
                    exception.getClass().getSimpleName()
            );
            return Optional.empty();
        }
    }

    private BigDecimal scoreFor(long failureCount, long mediumMinimum, long highMinimum) {
        if (failureCount >= highMinimum) {
            return properties.getHighScore();
        }
        if (failureCount >= mediumMinimum) {
            return properties.getMediumScore();
        }
        return BigDecimal.ZERO;
    }
}
