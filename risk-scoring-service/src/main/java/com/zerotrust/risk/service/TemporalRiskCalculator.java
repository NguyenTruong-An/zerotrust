package com.zerotrust.risk.service;

import com.zerotrust.risk.config.TemporalRiskProperties;
import com.zerotrust.risk.config.RiskPolicyProperties;
import com.zerotrust.risk.domain.RiskScoreModel;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.TemporalRiskAssessment;
import com.zerotrust.risk.repository.AuthenticationSuccessEventRepository;
import lombok.RequiredArgsConstructor;
import org.jboss.logging.Logger;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class TemporalRiskCalculator {

    private static final Logger LOGGER = Logger.getLogger(TemporalRiskCalculator.class);
    private static final BigDecimal ZERO = BigDecimal.ZERO;
    private static final int HOURS_PER_DAY = 24;

    private final AuthenticationSuccessEventRepository eventRepository;
    private final TemporalRiskProperties properties;
    private final RiskPolicyProperties policy;

    public TemporalRiskAssessment calculate(LoginContext context) {
        Objects.requireNonNull(context, "context must not be null");

        Instant evaluationTime = context.receivedAt();
        Instant windowStart = evaluationTime.minus(properties.getHistoryWindow());
        List<Instant> history;
        try {
            history = eventRepository.findRecentAuthenticationTimes(
                    context.subjectId(),
                    context.clientId(),
                    windowStart,
                    evaluationTime,
                    PageRequest.of(0, properties.getMaximumEvents())
            );
        } catch (DataAccessException exception) {
            LOGGER.warnf(
                    "Temporal-profile data is unavailable: reason=%s",
                    exception.getClass().getSimpleName()
            );
            return TemporalRiskAssessment.unavailable();
        }

        if (history.size() < properties.getMinimumEvents()) {
            return TemporalRiskAssessment.coldStart();
        }

        ZonedDateTime current = evaluationTime.atZone(properties.getZoneId());
        long matchingDays = history.stream()
                .map(eventTime -> eventTime.atZone(properties.getZoneId()))
                .filter(eventTime -> eventTime.getDayOfWeek() == current.getDayOfWeek())
                .count();
        long matchingHours = history.stream()
                .map(eventTime -> eventTime.atZone(properties.getZoneId()))
                .filter(eventTime -> circularHourDistance(
                        eventTime.getHour(),
                        current.getHour()
                ) <= properties.getHourTolerance())
                .count();

        if (policy.getModel() == RiskScoreModel.CONTINUOUS_B1) {
            return TemporalRiskAssessment.available(BehavioralRiskNormalizer.temporalRisk(
                    matchingDays, matchingHours, history.size(),
                    properties.getMinimumDayFrequency(), properties.getMinimumHourFrequency()));
        }

        boolean unusualDay = isBelowMinimumFrequency(
                matchingDays, history.size(), properties.getMinimumDayFrequency());
        boolean unusualHour = isBelowMinimumFrequency(
                matchingHours, history.size(), properties.getMinimumHourFrequency());

        if (unusualDay && unusualHour) {
            return TemporalRiskAssessment.available(properties.getHighScore());
        }
        if (unusualDay || unusualHour) {
            return TemporalRiskAssessment.available(properties.getMediumScore());
        }
        return TemporalRiskAssessment.available(ZERO);
    }

    private static boolean isBelowMinimumFrequency(
            long matches, int sampleSize, BigDecimal minimumFrequency
    ) {
        // Available profiles have a positive sample size; compare without rounding the ratio.
        return BigDecimal.valueOf(matches).compareTo(
                minimumFrequency.multiply(BigDecimal.valueOf(sampleSize))) < 0;
    }

    private static int circularHourDistance(int firstHour, int secondHour) {
        int directDistance = Math.abs(firstHour - secondHour);
        return Math.min(directDistance, HOURS_PER_DAY - directDistance);
    }
}
