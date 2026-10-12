package com.zerotrust.keycloak.risk.forms;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.UserLoginFailureProvider;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ZeroTrustLoginFormsProviderTest {
    private static final long NOW = 1_800_000_000L;

    @Test
    void usesPersistedUnlockTimeForPasswordLockout() {
        Fixture fixture = new Fixture();
        fixture.provider.setError(Messages.ACCOUNT_TEMPORARILY_DISABLED);

        fixture.provider.addLockoutAttribute("zerotrust", NOW);

        assertEquals(Map.of("remainingSeconds", 83L), fixture.provider.lockout());
    }

    @Test
    void usesSameAuthoritativeLockoutForOtpError() {
        Fixture fixture = new Fixture();
        fixture.provider.setError(Messages.ACCOUNT_TEMPORARILY_DISABLED_TOTP);

        fixture.provider.addLockoutAttribute("zerotrust", NOW + 20);

        assertEquals(Map.of("remainingSeconds", 63L), fixture.provider.lockout());
    }

    @Test
    void ordinaryInvalidCredentialsDoNotExposeLockoutDetails() {
        Fixture fixture = new Fixture();
        fixture.provider.setError(Messages.INVALID_USER);

        fixture.provider.addLockoutAttribute("zerotrust", NOW);

        assertNull(fixture.provider.lockout());
        verifyNoInteractions(fixture.failures);
    }

    @Test
    void permanentLockoutDoesNotGetCountdown() {
        Fixture fixture = new Fixture();
        fixture.provider.setError(Messages.ACCOUNT_PERMANENTLY_DISABLED);

        fixture.provider.addLockoutAttribute("zerotrust", NOW);

        assertNull(fixture.provider.lockout());
        verifyNoInteractions(fixture.failures);
    }

    @Test
    void otherThemesKeepNativeRenderingWithoutAdditionalLookup() {
        Fixture fixture = new Fixture();
        fixture.provider.setError(Messages.ACCOUNT_TEMPORARILY_DISABLED);

        fixture.provider.addLockoutAttribute("keycloak.v2", NOW);

        assertNull(fixture.provider.lockout());
        verifyNoInteractions(fixture.failures);
    }

    @Test
    void disabledAccountDoesNotGetCountdown() {
        Fixture fixture = new Fixture();
        fixture.provider.setError(Messages.ACCOUNT_TEMPORARILY_DISABLED);
        when(fixture.user.isEnabled()).thenReturn(false);

        fixture.provider.addLockoutAttribute("zerotrust", NOW);

        assertNull(fixture.provider.lockout());
        verifyNoInteractions(fixture.failures);
    }

    @Test
    void expiredLockoutClearsPreviousCountdown() {
        Fixture fixture = new Fixture();
        fixture.provider.setError(Messages.ACCOUNT_TEMPORARILY_DISABLED);
        fixture.provider.addLockoutAttribute("zerotrust", NOW);

        fixture.provider.addLockoutAttribute("zerotrust", NOW + 83);

        assertNull(fixture.provider.lockout());
    }

    @Test
    void missingFailureRecordDoesNotGuessWaitDuration() {
        Fixture fixture = new Fixture();
        fixture.provider.setError(Messages.ACCOUNT_TEMPORARILY_DISABLED);
        when(fixture.failures.getUserLoginFailure(fixture.realm, "user-1")).thenReturn(null);

        fixture.provider.addLockoutAttribute("zerotrust", NOW);

        assertNull(fixture.provider.lockout());
    }

    @Test
    void missingUserDoesNotLookUpArbitraryAccounts() {
        Fixture fixture = new Fixture();
        fixture.provider.setError(Messages.ACCOUNT_TEMPORARILY_DISABLED);
        fixture.provider.setUser(null);

        fixture.provider.addLockoutAttribute("zerotrust", NOW);

        assertNull(fixture.provider.lockout());
        verifyNoInteractions(fixture.failures);
    }

    @Test
    void disabledBruteForceProtectionDoesNotDisplayCountdown() {
        Fixture fixture = new Fixture();
        fixture.provider.setError(Messages.ACCOUNT_TEMPORARILY_DISABLED);
        when(fixture.realm.isBruteForceProtected()).thenReturn(false);

        fixture.provider.addLockoutAttribute("zerotrust", NOW);

        assertNull(fixture.provider.lockout());
        verifyNoInteractions(fixture.failures);
    }

    @Test
    void failureStoreOutageKeepsOriginalAuthenticationError() {
        Fixture fixture = new Fixture();
        fixture.provider.setError(Messages.ACCOUNT_TEMPORARILY_DISABLED);
        when(fixture.failures.getUserLoginFailure(fixture.realm, "user-1"))
                .thenThrow(new IllegalStateException("unavailable"));

        fixture.provider.addLockoutAttribute("zerotrust", NOW);

        assertNull(fixture.provider.lockout());
        assertEquals(Messages.ACCOUNT_TEMPORARILY_DISABLED, fixture.provider.errorMessage());
    }

    @Test
    void retainsNativeProviderIdWithHigherPriority() {
        ZeroTrustLoginFormsProviderFactory factory = new ZeroTrustLoginFormsProviderFactory();
        assertEquals("freemarker", factory.getId());
        assertEquals(100, factory.order());
    }

    private static final class Fixture {
        private final KeycloakSession session = mock(KeycloakSession.class);
        private final KeycloakContext context = mock(KeycloakContext.class);
        private final RealmModel realm = mock(RealmModel.class);
        private final UserModel user = mock(UserModel.class);
        private final UserLoginFailureProvider failures = mock(UserLoginFailureProvider.class);
        private final UserLoginFailureModel failure = mock(UserLoginFailureModel.class);
        private final InspectableProvider provider;

        private Fixture() {
            when(session.getContext()).thenReturn(context);
            when(context.getRealm()).thenReturn(realm);
            when(realm.isBruteForceProtected()).thenReturn(true);
            when(user.isEnabled()).thenReturn(true);
            when(user.getId()).thenReturn("user-1");
            when(session.loginFailures()).thenReturn(failures);
            when(failures.getUserLoginFailure(realm, "user-1")).thenReturn(failure);
            when(failure.getFailedLoginNotBefore()).thenReturn((int) (NOW + 83));
            provider = new InspectableProvider(session);
            provider.setUser(user);
        }
    }

    private static final class InspectableProvider extends ZeroTrustLoginFormsProvider {
        private InspectableProvider(KeycloakSession session) { super(session); }
        private Object lockout() { return attributes.get("ztLockout"); }
        private String errorMessage() { return getFirstMessageUnformatted(); }
    }
}
