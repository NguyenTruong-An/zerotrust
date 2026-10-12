package com.zerotrust.keycloak.risk.audit;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.zerotrust.keycloak.risk.authenticator.*;
import com.zerotrust.keycloak.risk.client.*;
import com.zerotrust.keycloak.risk.config.*;
import com.zerotrust.keycloak.risk.context.CookieDeviceIdResolver;
import com.zerotrust.keycloak.risk.dto.*;
import com.zerotrust.keycloak.risk.listener.RiskEventListenerFactory;
import jakarta.ws.rs.core.*;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.keycloak.authentication.*;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.ClientConnection;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.http.HttpResponse;
import org.keycloak.models.*;
import org.keycloak.sessions.*;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Real production factories/HTTP clients; stateful MOCK Keycloak models, not an engine. */
final class SpiAuditFixture implements AutoCloseable {
    static final String SUBJECT="2a000000-0000-4000-8000-000000000001";
    static final String SESSION="qa-root:qa-tab";
    static final String EVALUATE="/internal/v1/risk/evaluations";
    static final String REGISTER="/internal/v1/trusted-devices";
    static final String FAILURE="/internal/v1/authentication-failures";
    static final String SUCCESS="/internal/v1/authentication-successes";
    static final String TOKEN="/realms/qa02a/protocol/openid-connect/token";
    final AuthenticationFlowContext context=mock(AuthenticationFlowContext.class);
    final AuthenticationSessionModel auth=mock(AuthenticationSessionModel.class);
    final KeycloakSession session=mock(KeycloakSession.class);
    final RealmModel realm=mock(RealmModel.class);
    final UserModel user=mock(UserModel.class);
    final SubjectCredentialManager credentials=mock(SubjectCredentialManager.class);
    final ClientModel browserClient=mock(ClientModel.class);
    final RootAuthenticationSessionModel root=mock(RootAuthenticationSessionModel.class);
    final HttpHeaders headers=mock(HttpHeaders.class);
    final ClientConnection connection=mock(ClientConnection.class);
    final Map<String,String> notes=new HashMap<>();
    final Map<String,Cookie> cookies=new HashMap<>();
    final List<NewCookie> emitted=new ArrayList<>();
    final List<String> order=new CopyOnWriteArrayList<>();
    final List<WireCall> calls=new CopyOnWriteArrayList<>();
    final Set<String> requiredActions=new HashSet<>();
    final Map<String,AuthenticatorConfigModel> configs=new HashMap<>();
    final Map<String,List<AuthenticationExecutionModel>> executions=new HashMap<>();
    final Map<String,ReplyHandler> handlers=new ConcurrentHashMap<>();
    final RequiredActionProviderModel totpAction=new RequiredActionProviderModel();
    final AtomicInteger successes=new AtomicInteger();
    final AtomicInteger denials=new AtomicInteger();
    final AtomicInteger tokens=new AtomicInteger();
    final HttpServer server;
    final ExecutorService serverWorkers=Executors.newCachedThreadPool();
    final CloseableHttpClient http;
    final HttpClientProvider httpProvider=mock(HttpClientProvider.class);
    final RiskAuthenticatorFactory riskFactory=new RiskAuthenticatorFactory();
    final TrustedDeviceRegistrationAuthenticatorFactory registrationFactory=new TrustedDeviceRegistrationAuthenticatorFactory();
    final RiskEventListenerFactory eventFactory=new RiskEventListenerFactory();
    final AuthenticatorConfigModel config;

    SpiAuditFixture() throws IOException {
        server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.setExecutor(serverWorkers);
        server.createContext("/",this::dispatch);
        server.start();
        http=HttpClients.custom().disableAutomaticRetries().disableRedirectHandling().build();
        when(httpProvider.getHttpClient()).thenReturn(http);
        when(session.getProvider(HttpClientProvider.class)).thenReturn(httpProvider);
        when(context.getSession()).thenReturn(session);
        when(context.getAuthenticationSession()).thenReturn(auth);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUser()).thenReturn(user);
        when(user.getId()).thenReturn(SUBJECT);
        when(user.getRequiredActionsStream()).thenAnswer(i->requiredActions.stream());
        when(user.credentialManager()).thenReturn(credentials);
        when(context.getConnection()).thenReturn(connection);
        when(connection.getRemoteAddr()).thenReturn("203.0.113.22");
        HttpRequest request=mock(HttpRequest.class);
        when(context.getHttpRequest()).thenReturn(request);
        when(request.getHttpHeaders()).thenReturn(headers);
        when(headers.getCookies()).thenReturn(cookies);
        when(headers.getHeaderString("User-Agent")).thenReturn("QA02A/1.0");
        when(auth.getClient()).thenReturn(browserClient);
        when(browserClient.getClientId()).thenReturn("qa-browser");
        when(auth.getParentSession()).thenReturn(root);
        when(root.getId()).thenReturn("qa-root");
        when(auth.getTabId()).thenReturn("qa-tab");
        when(auth.getAuthNote(anyString())).thenAnswer(i->notes.get(i.getArgument(0)));
        doAnswer(i->{notes.put(i.getArgument(0),i.getArgument(1));return null;}).when(auth).setAuthNote(anyString(),anyString());
        doAnswer(i->{notes.remove(i.getArgument(0));return null;}).when(auth).removeAuthNote(anyString());
        doAnswer(i->{notes.clear();return null;}).when(auth).clearAuthNotes();
        when(auth.getRequiredActions()).thenReturn(Set.of());
        doAnswer(i->{successes.incrementAndGet();order.add("execution-success");return null;}).when(context).success();
        LoginFormsProvider form=mock(LoginFormsProvider.class);
        when(context.form()).thenReturn(form);
        when(form.setError(eq("accessDenied"))).thenReturn(form);
        when(form.createErrorPage(Response.Status.FORBIDDEN)).thenAnswer(i->Response.status(403).build());
        doAnswer(i->{denials.incrementAndGet();order.add("execution-denied");return null;}).when(context).failure(eq(AuthenticationFlowError.ACCESS_DENIED),any(Response.class),anyString(),anyString());
        totpAction.setAlias("CONFIGURE_TOTP");totpAction.setProviderId("CONFIGURE_TOTP");totpAction.setEnabled(true);
        when(realm.getRequiredActionProviderByAlias("CONFIGURE_TOTP")).thenReturn(totpAction);
        when(realm.getName()).thenReturn("qa02a");
        when(realm.getAuthenticatorConfigById(anyString())).thenAnswer(i->configs.get(i.getArgument(0)));
        when(realm.getAuthenticationExecutionsStream(anyString())).thenAnswer(i->executions.getOrDefault(i.getArgument(0),List.of()).stream());
        AuthenticationFlowModel flow=new AuthenticationFlowModel();flow.setId("qa-browser-flow");
        when(realm.getBrowserFlow()).thenReturn(flow);
        RealmProvider realms=mock(RealmProvider.class);
        when(session.realms()).thenReturn(realms);
        when(realms.getRealm("qa-realm")).thenReturn(realm);
        KeycloakContext kc=mock(KeycloakContext.class);
        when(session.getContext()).thenReturn(kc);
        when(kc.getRequestHeaders()).thenReturn(headers);
        org.keycloak.models.KeycloakUriInfo uri=mock(org.keycloak.models.KeycloakUriInfo.class);
        when(kc.getUri()).thenReturn(uri);
        when(uri.getBaseUri()).thenReturn(URI.create("https://qa.invalid/"));
        when(uri.getRequestUri()).thenReturn(URI.create("https://qa.invalid/realms/qa02a/login-actions/authenticate"));
        when(uri.getBaseUriBuilder()).thenAnswer(i->UriBuilder.fromUri("https://qa.invalid/"));
        HttpResponse response=mock(HttpResponse.class);
        when(kc.getHttpResponse()).thenReturn(response);
        doAnswer(i->{emitted.add(i.getArgument(0));order.add("cookie");return null;}).when(response).setCookieIfAbsent(any(NewCookie.class));
        config=addConfig("qa-risk","qa-browser");
        when(context.getAuthenticatorConfig()).thenReturn(config);
        executions.put("qa-browser-flow",List.of(evaluator("qa-risk",20,AuthenticationExecutionModel.Requirement.REQUIRED)));
        handlers.put(TOKEN,c->Reply.json(200,"{\"access_token\":\"qa-opaque-"+tokens.incrementAndGet()+"\",\"token_type\":\"Bearer\",\"expires_in\":3600}"));
        decision("ALLOW",0L,false);
        handlers.put(REGISTER,c->Reply.empty(204));
        handlers.put(FAILURE,c->Reply.empty(204));
        handlers.put(SUCCESS,c->Reply.empty(204));
    }
    String base(){return "http://127.0.0.1:"+server.getAddress().getPort();}
    AuthenticatorConfigModel addConfig(String id,String monitored){
        AuthenticatorConfigModel model=new AuthenticatorConfigModel();model.setId(id);
        model.setConfig(new HashMap<>(Map.of(
            "riskServiceBaseUrl",base(),"tokenEndpointUrl",base()+TOKEN,"serviceClientId","qa:caller+name",
            "serviceClientSecret","fixture: secret+only","failureMode","DENY","socketTimeoutMs","600",
            "connectTimeoutMs","500","connectionRequestTimeoutMs","500","monitoredEventClientId",monitored)));
        configs.put(id,model);return model;
    }
    static AuthenticationExecutionModel evaluator(String configId,int priority,AuthenticationExecutionModel.Requirement requirement){
        AuthenticationExecutionModel e=new AuthenticationExecutionModel();e.setId("exec-"+configId);e.setAuthenticator(RiskAuthenticatorFactory.PROVIDER_ID);e.setAuthenticatorConfig(configId);e.setPriority(priority);e.setRequirement(requirement);return e;
    }
    void decision(String decision,Long generation,boolean rotate){handlers.put(EVALUATE,c->Reply.json(200,evaluation(decision,generation,rotate)));}
    static String evaluation(String decision,Long generation,boolean rotate){return "{\"evaluationId\":\"2a000000-0000-4000-8000-000000000002\",\"subjectId\":\""+SUBJECT+"\",\"authenticationSessionId\":\""+SESSION+"\",\"riskScore\":"+(decision.equals("ALLOW")?"0":"90")+",\"riskLevel\":\""+(decision.equals("ALLOW")?"LOW":"HIGH")+"\",\"decision\":\""+decision+"\",\"dataStatus\":\"COMPLETE\",\"reasons\":"+(rotate?"[\"DEVICE_REAUTHENTICATION_REQUIRED\"]":"[]")+",\"evaluatedAt\":\"2026-10-12T01:00:00Z\",\"trustGeneration\":"+generation+"}";}
    Authenticator evaluator(){return riskFactory.create(session);}
    Authenticator registration(){return registrationFactory.create(session);}
    EventListenerProvider listener(){return eventFactory.create(session);}
    HttpRiskScoringClient client(){RiskAuthenticatorConfig cfg=new RiskAuthenticatorConfigResolver().resolve(config);return new HttpRiskScoringClient(httpProvider,cfg.clientConfig(),new ClientCredentialsTokenProvider(httpProvider,cfg.serviceTokenConfig(),cfg.clientConfig(),new ServiceTokenCache()));}
    List<WireCall> at(String path){return calls.stream().filter(c->c.path.equals(path)).toList();}
    void oldCookie(){cookies.put(CookieDeviceIdResolver.COOKIE_NAME,new Cookie(CookieDeviceIdResolver.COOKIE_NAME,"old-device-qa02a"));}
    void dispatch(HttpExchange exchange) throws IOException {
        String path=exchange.getRequestURI().getPath();
        WireCall call=new WireCall(path,exchange.getRequestMethod(),new String(exchange.getRequestBody().readAllBytes(),StandardCharsets.UTF_8),exchange.getRequestHeaders().getFirst("Authorization"));
        calls.add(call);order.add("wire:"+path);
        try{Reply reply=handlers.getOrDefault(path,c->Reply.empty(404)).handle(call);
            exchange.getResponseHeaders().set("Content-Type",reply.contentType);
            if(reply.location!=null)exchange.getResponseHeaders().set("Location",reply.location);
            byte[] body=reply.body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(reply.status,reply.status==204?-1:body.length);
            if(reply.status!=204)exchange.getResponseBody().write(body);
        }catch(InterruptedException e){Thread.currentThread().interrupt();}
        catch(Exception e){throw new IOException("QA stub failure",e);}
        finally{exchange.close();}
    }
    record WireCall(String path,String method,String body,String authorization){
        Map<?,?> json()throws IOException{return JsonSerialization.readValue(body,Map.class);}
        @Override public String toString(){return "WireCall[path="+path+", method="+method+", body/authorization=REDACTED]";}
    }
    record Reply(int status,String body,String contentType,String location){
        static Reply json(int status,String body){return new Reply(status,body,"application/json",null);}
        static Reply empty(int status){return json(status,"");}
    }
    interface ReplyHandler {Reply handle(WireCall call)throws Exception;}
    @Override public void close()throws IOException{riskFactory.close();registrationFactory.close();eventFactory.close();http.close();server.stop(0);serverWorkers.shutdownNow();}
}
