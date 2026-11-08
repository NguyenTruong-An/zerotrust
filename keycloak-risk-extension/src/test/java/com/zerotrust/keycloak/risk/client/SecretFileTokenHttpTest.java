package com.zerotrust.keycloak.risk.client;

import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfigResolver;
import com.sun.net.httpserver.HttpServer;
import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SecretFileTokenHttpTest {
    @Test void mountedSecretReachesOnlyTheTokenEndpointAndMissingFileFailsBeforeHttp(@TempDir Path directory)throws Exception{
        String marker="synthetic-PD06-mounted-client-secret-marker";
        Path file=directory.resolve("credential");Files.writeString(file,marker);
        if(Files.getFileStore(file).supportsFileAttributeView("posix"))Files.setPosixFilePermissions(file,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        AtomicReference<String> authorization=new AtomicReference<>();AtomicInteger calls=new AtomicInteger();
        HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/token",e->{
            authorization.set(e.getRequestHeaders().getFirst("Authorization"));calls.incrementAndGet();
            byte[] body="{\"access_token\":\"synthetic-token\",\"token_type\":\"Bearer\",\"expires_in\":300}".getBytes(StandardCharsets.UTF_8);
            e.getResponseHeaders().set("Content-Type","application/json");try{e.sendResponseHeaders(200,body.length);e.getResponseBody().write(body);}finally{e.close();}
        });server.start();
        try(var http=HttpClients.createDefault()){
            String base="http://127.0.0.1:"+server.getAddress().getPort();
            var model=new AuthenticatorConfigModel();var values=new HashMap<>(Map.of("riskServiceBaseUrl",base,"tokenEndpointUrl",base+"/token",
                    "serviceClientId","zerotrust-risk-caller","serviceClientSecretFile",file.toString()));model.setConfig(values);
            var config=new RiskAuthenticatorConfigResolver().resolve(model);
            var provider=mock(HttpClientProvider.class);when(provider.getHttpClient()).thenReturn(http);
            var token=new ClientCredentialsTokenProvider(provider,config.serviceTokenConfig(),config.clientConfig(),new ServiceTokenCache());
            assertEquals("synthetic-token",token.accessToken());assertEquals("synthetic-token",token.accessToken());assertEquals(1,calls.get());
            assertEquals("Basic "+Base64.getEncoder().encodeToString(("zerotrust-risk-caller:"+marker).getBytes(StandardCharsets.UTF_8)),authorization.get());
            values.put("serviceClientSecretFile",directory.resolve("missing").toString());model.setConfig(values);
            assertThrows(RuntimeException.class,()->new RiskAuthenticatorConfigResolver().resolve(model));assertEquals(1,calls.get());
        }finally{server.stop(0);}
    }
}
