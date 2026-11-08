package com.zerotrust.keycloak.risk.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.models.AuthenticatorConfigModel;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class PublicDemoServiceSecretsTest {
    static final String MARKER="synthetic-PD06-never-log-secret-marker";
    static Map<String,String> environment(){return Map.of("PUBLIC_DEMO_MODE","public-demo","PUBLIC_DEMO_ACADEMIC_READ_ONLY","true",
            "PUBLIC_DEMO_RISK_CALLER_SECRET_FILE",PublicDemoServiceSecrets.SECRET_FILE);}
    static Map<String,String> config(){return new HashMap<>(Map.of("riskServiceBaseUrl","https://risk.internal","tokenEndpointUrl","https://auth.example.invalid/realms/demo/token",
            "serviceClientId","zerotrust-risk-caller","serviceClientSecretFile",PublicDemoServiceSecrets.SECRET_FILE));}
    @Test void productionUsesOnlyFixedFileAndCorrectServiceIdentity(){
        var secrets=new PublicDemoServiceSecrets(environment(),path->{assertEquals(PublicDemoServiceSecrets.SECRET_FILE,path);return MARKER;});
        secrets.validateStartup();var model=new AuthenticatorConfigModel();model.setConfig(config());
        var result=new RiskAuthenticatorConfigResolver(secrets).resolve(model);
        assertEquals(MARKER,result.serviceTokenConfig().clientSecret());assertFalse(result.toString().contains(MARKER));
    }
    @ParameterizedTest @ValueSource(strings={"serviceClientSecret","serviceClientSecretFile","serviceClientId","riskServiceBaseUrl","tokenEndpointUrl"})
    void unsafeProductionReferenceOrCallerIsRejected(String key){
        var c=config();c.put(key,key.equals("serviceClientSecret")?MARKER:"http://localhost/"+MARKER);
        var ex=assertThrows(RuntimeException.class,()->new PublicDemoServiceSecrets(environment(),p->MARKER).resolve(c));assertSafe(ex);
    }
    @Test void missingPublicModeFlagOrStartupReferenceFails(){
        for(String key:environment().keySet()){
            var env=new HashMap<>(environment());env.remove(key);
            assertThrows(RuntimeException.class,()->new PublicDemoServiceSecrets(env,p->MARKER).validateStartup());
        }
    }
    @Test void labInlineSecretBehaviorAndFileReferenceAreSeparate(@TempDir Path dir)throws Exception{
        var legacy=new PublicDemoServiceSecrets(Map.of(),PublicDemoServiceSecrets::readFile);
        assertEquals("legacy-secret",legacy.resolve(Map.of("serviceClientSecret","legacy-secret")));
        Path file=dir.resolve("fixture");Files.writeString(file,MARKER+"\n");
        if(Files.getFileStore(file).supportsFileAttributeView("posix"))Files.setPosixFilePermissions(file,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        assertEquals(MARKER,legacy.resolve(Map.of("serviceClientSecretFile",file.toString())));
        assertThrows(RuntimeException.class,()->legacy.resolve(Map.of("serviceClientSecretFile",file.toString(),"serviceClientSecret",MARKER)));
    }
    @ParameterizedTest @ValueSource(strings={"", "short", "                ", "synthetic-PD06-never-log-secret-marker\nsecond-line"})
    void invalidSyntheticFileIsRedacted(String contents,@TempDir Path dir)throws Exception{
        Path file=dir.resolve("fixture");Files.writeString(file,contents);
        assertSafe(assertThrows(RuntimeException.class,()->PublicDemoServiceSecrets.readFile(file.toString())));
    }
    @Test void missingDirectoryAndOversizedFilesAreRejected(@TempDir Path dir)throws Exception{
        for(Path p:List.of(dir,dir.resolve("missing-"+MARKER)))assertSafe(assertThrows(RuntimeException.class,()->PublicDemoServiceSecrets.readFile(p.toString())));
        Path file=dir.resolve("fixture");Files.writeString(file,MARKER.repeat(200));
        assertSafe(assertThrows(RuntimeException.class,()->PublicDemoServiceSecrets.readFile(file.toString())));
    }
    @ParameterizedTest @ValueSource(strings={"riskServiceBaseUrl","tokenEndpointUrl","connectTimeoutMs","tokenRefreshSkewMs","failureMode"})
    void parserExceptionNeverRetainsCredentialBearingCauses(String key){
        var c=config();c.remove("serviceClientSecretFile");c.put("serviceClientSecret",MARKER);
        c.put(key,"https://user:"+MARKER+"@[invalid uri");var model=new AuthenticatorConfigModel();model.setConfig(c);
        assertSafe(assertThrows(RuntimeException.class,()->new RiskAuthenticatorConfigResolver(new PublicDemoServiceSecrets(Map.of(),p->MARKER)).resolve(model)));
    }
    static void assertSafe(Throwable ex){var writer=new java.io.StringWriter();ex.printStackTrace(new java.io.PrintWriter(writer));assertFalse(writer.toString().contains(MARKER));}
}
