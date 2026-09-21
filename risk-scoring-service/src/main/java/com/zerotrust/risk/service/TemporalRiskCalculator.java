package com.zerotrust.risk.service;

import com.zerotrust.risk.config.TemporalRiskProperties;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.TemporalRiskAssessment;
import com.zerotrust.risk.repository.AuthenticationSuccessEventRepository;
import lombok.RequiredArgsConstructor;
import org.jboss.logging.Logger;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class TemporalRiskCalculator {

    private static final Logger LOGGER = Logger.getLogger(TemporalRiskCalculator.class);
    private static final BigDecimal ZERO = BigDecimal.ZERO;
    private static final int FREQUENCY_SCALE = 6;
    private static final int HOURS_PER_DAY = 24;

    private final AuthenticationSuccessEventRepository eventRepository;
    private final TemporalRiskProperties properties;

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

        boolean unusualDay = frequency(matchingDays, history.size())
                .compareTo(properties.getMinimumDayFrequency()) < 0;
        boolean unusualHour = frequency(matchingHours, history.size())
                .compareTo(properties.getMinimumHourFrequency()) < 0;

        if (unusualDay && unusualHour) {
            return TemporalRiskAssessment.available(properties.getHighScore());
        }
        if (unusualDay || unusualHour) {
            return TemporalRiskAssessment.available(properties.getMediumScore());
        }
        return TemporalRiskAssessment.available(ZERO);
    }

    private static BigDecimal frequency(long matches, int sampleSize) {
        return BigDecimal.valueOf(matches).divide(
                BigDecimal.valueOf(sampleSize),
                FREQUENCY_SCALE,
                RoundingMode.HALF_UP
        );
    }

    private static int circularHourDistance(int firstHour, int secondHour) {
        int directDistance = Math.abs(firstHour - secondHour);
        return Math.min(directDistance, HOURS_PER_DAY - directDistance);
    }
}
