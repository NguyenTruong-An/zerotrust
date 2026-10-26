package com.zerotrust.zerotrust.model.validation;

import jakarta.validation.Constraint;
import jakarta.validation.OverridesAttribute;
import jakarta.validation.Payload;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Digits;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE_USE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/** Validates an optional score; use NotNull separately for required score components. */
@Documented
@Target({FIELD, PARAMETER, ANNOTATION_TYPE, TYPE_USE})
@Retention(RUNTIME)
@Constraint(validatedBy = {})
@DecimalMin("0.0")
@DecimalMax("10.0")
@Digits(integer = 2, fraction = 2)
public @interface ScoreValue {
    String message() default "Score is invalid";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    @OverridesAttribute(constraint = DecimalMin.class, name = "message")
    String minMessage() default "Score must be at least 0";

    @OverridesAttribute(constraint = DecimalMax.class, name = "message")
    String maxMessage() default "Score must not exceed 10";

    @OverridesAttribute(constraint = Digits.class, name = "message")
    String precisionMessage() default "Score must have at most 2 decimal places";
}
