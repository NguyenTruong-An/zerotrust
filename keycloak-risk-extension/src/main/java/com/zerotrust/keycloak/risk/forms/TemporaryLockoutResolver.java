package com.zerotrust.keycloak.risk.forms;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.UserModel;

import java.util.OptionalLong;

final class TemporaryLockoutResolver {

    OptionalLong remainingSeconds(KeycloakSession session, RealmModel realm, UserModel user, long nowSeconds) {
        if (realm == null || user == null || !realm.isBruteForceProtected() || !user.isEnabled()) {
            return OptionalLong.empty();
        }
        UserLoginFailureModel failure = session.loginFailures().getUserLoginFailure(realm, user.getId());
        if (failure == null) {
            return OptionalLong.empty();
        }
        long remaining = (long) failure.getFailedLoginNotBefore() - nowSeconds;
        return remaining > 0 ? OptionalLong.of(remaining) : OptionalLong.empty();
    }
}
