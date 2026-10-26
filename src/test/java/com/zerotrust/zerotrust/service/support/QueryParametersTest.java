package com.zerotrust.zerotrust.service.support;

import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.data.domain.Sort;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class QueryParametersTest {
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void usesDefaultSortForMissingInput(String input) {
        assertThat(QueryParameters.parseSort(input, "academicYear,desc", Set.of("academicYear")))
                .isEqualTo(Sort.by(Sort.Direction.DESC, "academicYear"));
    }

    @Test
    void mapsPublicSortAliasToEntityProperty() {
        assertThat(QueryParameters.parseSort(
                " username , dEsC ", "username,asc", Map.of("username", "userEntity.username")))
                .isEqualTo(Sort.by(Sort.Direction.DESC, "userEntity.username"));
    }

    @Test
    void fieldWithoutDirectionUsesAscendingOrder() {
        assertThat(QueryParameters.parseSort("academicYear", "academicYear,desc", Set.of("academicYear")))
                .isEqualTo(Sort.by(Sort.Direction.ASC, "academicYear"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"username,", "username,sideways", "username,asc,desc", ",asc",
            "unknown,asc", "userEntity.username,asc"})
    void rejectsMalformedOrUnlistedSortsForBothAllowlists(String input) {
        assertInvalidSort(() -> QueryParameters.parseSort(input, "username,asc", Set.of("username")));
        assertInvalidSort(() -> QueryParameters.parseSort(
                input, "username,asc", Map.of("username", "userEntity.username")));
    }

    @ParameterizedTest
    @CsvSource({"-1,20,Page must be zero or greater", "0,0,Size must be between 1 and 100",
            "0,101,Size must be between 1 and 100"})
    void rejectsPaginationOutsideBounds(int page, int size, String message) {
        assertThatThrownBy(() -> QueryParameters.validatePagination(page, size))
                .isInstanceOfSatisfying(WebException.class, exception -> {
                    assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_REQUEST);
                    assertThat(exception.getDetails()).isEqualTo(message);
                });
    }

    @ParameterizedTest
    @CsvSource({"0,1", "0,100", "2147483647,100"})
    void acceptsPaginationAtBounds(int page, int size) {
        assertThatCode(() -> QueryParameters.validatePagination(page, size)).doesNotThrowAnyException();
    }

    private void assertInvalidSort(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOfSatisfying(WebException.class, exception -> {
            assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_REQUEST);
            assertThat(exception.getDetails())
                    .isEqualTo("Sort must use an allowed field followed by asc or desc");
        });
    }
}
