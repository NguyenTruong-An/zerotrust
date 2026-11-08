package com.zerotrust.zerotrust.identity.keycloak;

import com.zerotrust.zerotrust.config.KeycloakAdminProperties;
import com.zerotrust.zerotrust.identity.model.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.*;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.boot.test.system.*;
import java.time.Duration;
import java.util.UUID;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;

@ExtendWith(OutputCaptureExtension.class)
class KeycloakRollbackLoggingTest {
    @Test void rollbackNeverLogsProviderBodyTokenPasswordOrNestedException(CapturedOutput output){
        String marker="synthetic-PD06-secret-otp-cookie-privatekey-marker";
        Keycloak kc=mock(Keycloak.class);RealmResource realm=mock(RealmResource.class);UsersResource users=mock(UsersResource.class);UserResource user=mock(UserResource.class);
        var props=new KeycloakAdminProperties("https://auth.invalid","demo","identity",marker,Duration.ofSeconds(1),Duration.ofSeconds(1),Duration.ofSeconds(1),2,10);
        var client=new KeycloakUserClient(kc,props,new KeycloakExceptionMapper());UUID id=UUID.randomUUID();
        when(kc.realm("demo")).thenReturn(realm);when(realm.users()).thenReturn(users);when(users.get(id.toString())).thenReturn(user);
        doThrow(new RuntimeException("Authorization: Bearer "+marker,new IllegalArgumentException("password="+marker))).when(user).remove();
        client.deleteUserQuietly(new ProvisionedIdentityUser(id));
        when(user.toRepresentation()).thenReturn(new UserRepresentation());
        doThrow(new RuntimeException("OTP/TrustedDevice="+marker)).when(user).update(any());
        client.restoreUserProfileQuietly(id,new IdentityUserProfileSnapshot(marker,marker,marker,false));
        assertThat(output.getAll()).contains("stage=delete","stage=profile").doesNotContain(marker,id.toString());
    }
}
