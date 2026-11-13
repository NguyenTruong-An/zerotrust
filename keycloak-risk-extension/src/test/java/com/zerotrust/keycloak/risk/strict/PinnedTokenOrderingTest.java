package com.zerotrust.keycloak.risk.strict;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.token.*;
import org.keycloak.representations.*;
import java.net.*;
import java.nio.file.Path;
import java.lang.reflect.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
/** Exact running-image bytes, but mocked native dependencies: not a browser integration test. */
@EnabledIfSystemProperty(named="keycloak.runtime.services.jar",matches=".+")
class PinnedTokenOrderingTest {
    @Test void exactResponseBuilderRunsVetoEvenBeforeCachedResponseAndAnyTokenEncoder()throws Exception {
        URL jar=Path.of(System.getProperty("keycloak.runtime.services.jar")).toUri().toURL();
        try(var loader=new URLClassLoader(new URL[]{jar},getClass().getClassLoader()){
            @Override protected Class<?> loadClass(String name,boolean resolve)throws ClassNotFoundException{
                if(name.equals("org.keycloak.protocol.oidc.TokenManager") || name.startsWith("org.keycloak.protocol.oidc.TokenManager$")){
                    synchronized(getClassLoadingLock(name)){Class<?> c=findLoadedClass(name);if(c==null)c=findClass(name);if(resolve)resolveClass(c);return c;}
                }return super.loadClass(name,resolve);
            }
        }) {
            var manager=loader.loadClass("org.keycloak.protocol.oidc.TokenManager");var builder=loader.loadClass("org.keycloak.protocol.oidc.TokenManager$AccessTokenResponseBuilder");
            assertEquals(jar,builder.getProtectionDomain().getCodeSource().getLocation());
            var s=mock(KeycloakSession.class,RETURNS_DEEP_STUBS);var factory=mock(TokenPostProcessorFactory.class);var veto=mock(TokenPostProcessor.class);
            when(factory.getId()).thenReturn("veto");when(s.getKeycloakSessionFactory().getProviderFactoriesStream(TokenPostProcessor.class)).thenAnswer(i->Stream.of(factory));doReturn(veto).when(s).getProvider(TokenPostProcessor.class,"veto");
            RuntimeException rejection=new RuntimeException("fixture-veto");doThrow(rejection).when(veto).process(any());
            Object b=builder.getConstructors()[0].newInstance(mock(RealmModel.class),mock(ClientModel.class),null,s,null,null,manager.getConstructor().newInstance());
            var cached=builder.getDeclaredField("response");cached.setAccessible(true);cached.set(b,new AccessTokenResponse());
            var failure=assertThrows(InvocationTargetException.class,()->builder.getMethod("build").invoke(b));assertSame(rejection,failure.getCause());verify(s,never()).tokens();verify(veto).process(any());
        }
    }
}
