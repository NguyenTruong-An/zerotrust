package com.zerotrust.risk.service;

import com.zerotrust.risk.config.AuthenticationHistoryRiskProperties;
import com.zerotrust.risk.domain.AuthenticationHistoryRiskAssessment;
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

    public Optional<AuthenticationHistoryRiskAssessment> calculate(LoginContext context) {
        Objects.requireNonNull(context, "context must not be null");

        try {
            long subjectFailures = failureStore.countBySubject(context.subjectId());
            long sourceIpFailures = failureStore.countBySourceIp(context.ipAddress());
            BigDecimal subjectRisk = scoreFor(
                    subjectFailures,
                    properties.getSubjectMediumMinimum(),
                    properties.getSubjectHighMinimum()
            );
            BigDecimal sourceIpRisk = scoreFor(
                    sourceIpFailures,
                    properties.getSourceIpMediumMinimum(),
                    properties.getSourceIpHighMinimum()
            );

            // One failure normally contributes to both counters. Taking the maximum avoids
            // double-counting while retaining the stronger account or network signal.
            return Optional.of(new AuthenticationHistoryRiskAssessment(
                    subjectRisk.max(sourceIpRisk),
                    subjectFailures >= properties.getSubjectHighMinimum()
                            || sourceIpFailures >= properties.getSourceIpHighMinimum()
            ));
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
