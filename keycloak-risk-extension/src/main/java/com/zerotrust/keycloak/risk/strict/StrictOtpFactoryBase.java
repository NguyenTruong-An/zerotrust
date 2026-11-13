package com.zerotrust.keycloak.risk.strict;
import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
/** Reuses Keycloak's factory lifecycle defaults, never its OTP implementation for ticket checks. */
public abstract class StrictOtpFactoryBase extends OTPFormAuthenticatorFactory {
    @Override public boolean isUserSetupAllowed(){return false;}
    @Override public String getReferenceCategory(){return null;}
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices(){return new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED};}
}
