package com.zerotrust.keycloak.risk.forms;

import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.Response;
import com.zerotrust.keycloak.risk.trace.RiskEvaluationTrace;
import static com.zerotrust.keycloak.risk.trace.RiskEvaluationTrace.Stage.MFA_FORM;
import static com.zerotrust.keycloak.risk.trace.RiskEvaluationTrace.Outcome.*;
import org.keycloak.common.util.Time;
import org.keycloak.forms.login.LoginFormsPages;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.theme.Theme;

import java.util.Locale;
import java.util.Map;
import java.util.Properties;

public class ZeroTrustLoginFormsProvider extends FreeMarkerLoginFormsProvider {

    private final TemporaryLockoutResolver lockoutResolver = new TemporaryLockoutResolver();
    private final RiskEvaluationTrace trace;

    public ZeroTrustLoginFormsProvider(KeycloakSession session) {
        this(session, RiskEvaluationTrace.DEFAULT);
    }

    ZeroTrustLoginFormsProvider(KeycloakSession session, RiskEvaluationTrace trace) {
        super(session);
        this.trace = trace;
    }

    @Override
    protected Response createResponse(LoginFormsPages page) {
        Response response = super.createResponse(page);
        traceMfaForm(page, response);
        return response;
    }

    void traceMfaForm(LoginFormsPages page, Response response) {
        // Observe the rendered form, never the submitted form data or credential.
        try {
            if (response != null && response.getStatus() == 200
                && (page == LoginFormsPages.LOGIN_TOTP
                    || page == LoginFormsPages.LOGIN_RECOVERY_AUTHN_CODES_INPUT)) {
                trace.form(authenticationSession, MFA_FORM, CHALLENGE_RENDERED);
                if (page == LoginFormsPages.LOGIN_TOTP && messages != null && messages.stream()
                        .anyMatch(message -> Messages.INVALID_TOTP.equals(message.getMessage()))) {
                    trace.form(authenticationSession, MFA_FORM, MFA_INPUT_REJECTED);
                }
            }
        } catch (RuntimeException ignored) {
            // Observing a form must never replace Keycloak's response.
        }
    }

    @Override
    protected void createCommonAttributes(Theme theme, Locale locale, Properties messagesBundle,
                                          UriBuilder baseUriBuilder, LoginFormsPages page) {
        super.createCommonAttributes(theme, locale, messagesBundle, baseUriBuilder, page);
        addLockoutAttribute(theme.getName(), Time.currentTime());
    }

    void addLockoutAttribute(String themeName, long nowSeconds) {
        attributes.remove("ztLockout");
        if (!"zerotrust".equals(themeName) || messages == null || messages.stream().noneMatch(message ->
                Messages.ACCOUNT_TEMPORARILY_DISABLED.equals(message.getMessage())
                        || Messages.ACCOUNT_TEMPORARILY_DISABLED_TOTP.equals(message.getMessage()))) {
            return;
        }
        try {
            UserModel lockedUser = user;
            if (lockedUser == null && authenticationSession != null) {
                lockedUser = AuthenticationManager.lookupUserForBruteForceLog(session, realm, authenticationSession);
            }
            lockoutResolver.remainingSeconds(session, realm, lockedUser, nowSeconds).ifPresent(remaining ->
                    attributes.put("ztLockout", Map.of("remainingSeconds", remaining)));
        } catch (RuntimeException ignored) {
            // Countdown is presentation only. The original Keycloak error still applies
            // when its lockout state cannot be read; never guess a duration or change it.
        }
    }
}
