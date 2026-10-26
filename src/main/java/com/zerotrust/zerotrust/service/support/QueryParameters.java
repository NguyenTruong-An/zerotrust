package com.zerotrust.zerotrust.service.support;

import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import org.springframework.data.domain.Sort;

import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/** Shared validation for paginated Portal queries. Sort fields are explicitly allowlisted. */
public final class QueryParameters {
    private static final int MAX_PAGE_SIZE = 100;

    private QueryParameters() {
    }

    public static void validatePagination(int page, int size) {
        if (page < 0) {
            throw new WebException(ErrorCode.INVALID_REQUEST, "Page must be zero or greater");
        }
        if (size < 1 || size > MAX_PAGE_SIZE) {
            throw new WebException(ErrorCode.INVALID_REQUEST, "Size must be between 1 and " + MAX_PAGE_SIZE);
        }
    }

    public static Sort parseSort(String sort, String defaultSort, Set<String> allowedProperties) {
        return parseSort(sort, defaultSort, property -> allowedProperties.contains(property) ? property : null);
    }

    public static Sort parseSort(String sort, String defaultSort, Map<String, String> allowedProperties) {
        return parseSort(sort, defaultSort, allowedProperties::get);
    }

    private static Sort parseSort(String sort, String defaultSort, Function<String, String> resolveProperty) {
        String normalizedSort = normalizeOptional(sort);
        String[] parts = (normalizedSort == null ? defaultSort : normalizedSort).split(",", -1);
        if (parts.length > 2) {
            throw invalidSort();
        }

        String property = resolveProperty.apply(parts[0].trim());
        if (property == null) {
            throw invalidSort();
        }

        Sort.Direction direction = Sort.Direction.ASC;
        if (parts.length == 2) {
            try {
                direction = Sort.Direction.fromString(parts[1].trim());
            } catch (IllegalArgumentException ex) {
                throw invalidSort();
            }
        }
        return Sort.by(direction, property);
    }

    public static String normalizeOptional(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static WebException invalidSort() {
        return new WebException(
                ErrorCode.INVALID_REQUEST,
                "Sort must use an allowed field followed by asc or desc");
    }
}
