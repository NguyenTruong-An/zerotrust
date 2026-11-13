package com.zerotrust.keycloak.risk;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.IDToken;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Executes mapper classes copied read-only from the exact running image, not Maven's same-version jar. */
@EnabledIfSystemProperty(named="keycloak.runtime.services.jar", matches=".+")
class PinnedUserSessionNoteMapperTest {
    private static final String MAPPER="org.keycloak.protocol.oidc.mappers.UserSessionNoteMapper";

    private URLClassLoader loader() throws Exception {
        URL artifact=Path.of(System.getProperty("keycloak.runtime.services.jar")).toUri().toURL();
        return new URLClassLoader(new URL[]{artifact}, getClass().getClassLoader()) {
            @Override protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                synchronized(getClassLoadingLock(name)) {
                    if (name.startsWith("org.keycloak.protocol.oidc.mappers.")) {
                        Class<?> value=findLoadedClass(name);
                        if (value==null) value=findClass(name);
                        if (resolve) resolveClass(value);
                        return value;
                    }
                    return super.loadClass(name,resolve);
                }
            }
        };
    }

    private IDToken map(Class<?> mapperClass, Object mapper, UserSessionModel session) throws Exception {
        ProtocolMapperModel config=new ProtocolMapperModel();
        config.setConfig(new HashMap<>(Map.of("user.session.note","zerotrust.mfa.at", "claim.name","zt_mfa_at", "jsonType.label","long")));
        var method=mapperClass.getDeclaredMethod("setClaim",IDToken.class,ProtocolMapperModel.class,UserSessionModel.class);
        method.setAccessible(true);
        IDToken token=new IDToken(); method.invoke(mapper,token,config,session); return token;
    }

    @Test void exactRuntimeMapperCanPublishServerNoteWithoutRenewingFactorTime() throws Exception {
        try(var loader=loader()) {
            Class<?> type=loader.loadClass(MAPPER);
            assertEquals(Path.of(System.getProperty("keycloak.runtime.services.jar")).toUri().toURL(), type.getProtectionDomain().getCodeSource().getLocation());
            Object mapper=type.getConstructor().newInstance();
            UserSessionModel session=mock(UserSessionModel.class);
            when(session.getNote("zerotrust.mfa.at")).thenReturn("1794528000");
            assertEquals(1794528000L,map(type,mapper,session).getOtherClaims().get("zt_mfa_at"));
            assertEquals(1794528000L,map(type,mapper,session).getOtherClaims().get("zt_mfa_at"));
            verify(session,never()).setNote(anyString(),anyString());
        }
    }

    @Test void exactRuntimeMapperDoesNotInventProofWhenNoteIsAbsent() throws Exception {
        try(var loader=loader()) {
            Class<?> type=loader.loadClass(MAPPER);
            IDToken token=map(type,type.getConstructor().newInstance(),mock(UserSessionModel.class));
            assertFalse(token.getOtherClaims().containsKey("zt_mfa_at"));
        }
    }
}
