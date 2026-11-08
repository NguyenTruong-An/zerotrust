package com.zerotrust.zerotrust.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Explicitly reviewed Portal handlers. Unclassified handlers are denied in Public Demo. */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface PublicDemoEndpoint {
    Kind value();

    enum Kind { READ, SECURITY_STATE }
}
