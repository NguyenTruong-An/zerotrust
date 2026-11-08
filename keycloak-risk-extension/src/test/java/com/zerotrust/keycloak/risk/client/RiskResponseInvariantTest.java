package com.zerotrust.keycloak.risk.client;

import com.zerotrust.keycloak.risk.config.RiskScoringClientConfig;
import com.zerotrust.keycloak.risk.dto.RiskEvaluationRequest;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicStatusLine;
import org.apache.http.HttpVersion;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RiskResponseInvariantTest {
    private static final String NONCE = "X-ZeroTrust-Risk-Request";

    @ParameterizedTest
    @CsvSource({
            "10,LOW,ALLOW,INCOMPLETE", "null,LOW,ALLOW,COMPLETE",
            "90,HIGH,ALLOW,COMPLETE", "50,MEDIUM,ALLOW,COMPLETE",
            "10,LOW,STEP_UP_MFA,COMPLETE", "90,HIGH,STEP_UP_MFA,COMPLETE",
            "10,LOW,DENY,COMPLETE", "null,MEDIUM,STEP_UP_MFA,COMPLETE",
            "-1,LOW,ALLOW,COMPLETE", "101,LOW,ALLOW,COMPLETE",
            "10.123,LOW,ALLOW,COMPLETE", "10,LOW,ALLOW,NOT_EVALUATED",
            "10,MEDIUM,STEP_UP_MFA,INCOMPLETE", "null,HIGH,ALLOW,NOT_EVALUATED"
    })
    void inconsistentHttp200CannotBecomeAnAuthenticationDecision(String score, String level, String decision,
                                                               String status) throws Exception {
        CloseableHttpClient http = mock(CloseableHttpClient.class);
        when(http.execute(any(HttpUriRequest.class))).thenAnswer(call ->
                response(call.getArgument(0), json(score, level, decision, status), null));
        RiskScoringClientException failure = assertThrows(RiskScoringClientException.class,
                () -> client(http).evaluate(request()));
        assertEquals(RiskScoringClientException.FailureType.INVALID_RESPONSE, failure.failureType());
    }

    @Test
    void oldReplyForTheSameSubjectAndAuthenticationSessionCannotSatisfyAnotherCall() throws Exception {
        CloseableHttpClient http = mock(CloseableHttpClient.class);
        AtomicReference<String> first = new AtomicReference<>();
        when(http.execute(any(HttpUriRequest.class))).thenAnswer(call -> {
            HttpUriRequest request = call.getArgument(0);
            var header = request.getFirstHeader(NONCE);
            String nonce = header == null ? null : header.getValue();
            if (first.get() == null) first.set(nonce);
            return response(request, json("10", "LOW", "ALLOW", "COMPLETE"), first.get());
        });
        HttpRiskScoringClient client = client(http);
        client.evaluate(request());
        assertThrows(RiskScoringClientException.class, () -> client.evaluate(request()));
        assertNotNull(first.get());
    }

    @ParameterizedTest
    @CsvSource({"10,LOW,ALLOW,COMPLETE", "25,MEDIUM,STEP_UP_MFA,COMPLETE",
            "null,MEDIUM,STEP_UP_MFA,INCOMPLETE", "80,HIGH,DENY,COMPLETE",
            "null,HIGH,DENY,NOT_EVALUATED"})
    void realCompleteMandatoryIncompleteAndPriorityContractsRemainValid(String score, String level,
                                                                       String decision, String status) throws Exception {
        CloseableHttpClient http = mock(CloseableHttpClient.class);
        when(http.execute(any(HttpUriRequest.class))).thenAnswer(call ->
                response(call.getArgument(0), json(score, level, decision, status), null));
        assertEquals(decision, client(http).evaluate(request()).decision().name());
    }

    private static CloseableHttpResponse response(HttpUriRequest request, String body, String override) {
        CloseableHttpResponse response = mock(CloseableHttpResponse.class);
        when(response.getStatusLine()).thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, 200, "OK"));
        when(response.getEntity()).thenReturn(new StringEntity(body, ContentType.APPLICATION_JSON));
        var sent = request.getFirstHeader(NONCE);
        if (sent != null) {
            var header = new BasicHeader(NONCE, override == null ? sent.getValue() : override);
            when(response.getFirstHeader(NONCE)).thenReturn(header);
            when(response.getHeaders(NONCE)).thenReturn(new org.apache.http.Header[]{header});
        }
        return response;
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings={"missing","duplicate"})
    void responseMustHaveExactlyOneMatchingAttemptNonce(String mode)throws Exception{
        CloseableHttpClient http=mock(CloseableHttpClient.class);
        when(http.execute(any(HttpUriRequest.class))).thenAnswer(call->{
            HttpUriRequest request=call.getArgument(0);
            CloseableHttpResponse reply=response(request,json("10","LOW","ALLOW","COMPLETE"),null);
            if(mode.equals("missing")) when(reply.getFirstHeader(NONCE)).thenReturn(null);
            else {
                var echoed=reply.getFirstHeader(NONCE);
                when(reply.getHeaders(NONCE)).thenReturn(new org.apache.http.Header[]{echoed,echoed});
            }
            return reply;
        });
        assertThrows(RiskScoringClientException.class,()->client(http).evaluate(request()));
    }

    private static HttpRiskScoringClient client(CloseableHttpClient http) {
        ServiceTokenProvider tokens = new ServiceTokenProvider() {
            public String accessToken() { return "synthetic-service-token"; }
            public void invalidate(String token) { }
        };
        return new HttpRiskScoringClient(http, RiskScoringClientConfig.defaults(URI.create("https://risk.test")), tokens);
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings={"trailing-object","trailing-garbage","duplicate-decision","duplicate-score","numeric-decision"})
    void malformedOrAmbiguousJsonCannotBeAnAllowResponse(String mode)throws Exception{
        String valid=json("10","LOW","ALLOW","COMPLETE");
        String body=switch(mode){
            case "trailing-object"->valid+" {\"decision\":\"DENY\"}";
            case "trailing-garbage"->valid+" invalid-json";
            case "duplicate-decision"->valid.replace("\"decision\":\"ALLOW\"","\"decision\":\"DENY\",\"decision\":\"ALLOW\"");
            case "duplicate-score"->valid.replace("\"riskScore\":10","\"riskScore\":90,\"riskScore\":10");
            default->valid.replace("\"decision\":\"ALLOW\"","\"decision\":0");
        };
        CloseableHttpClient http=mock(CloseableHttpClient.class);
        when(http.execute(any(HttpUriRequest.class))).thenAnswer(call->response(call.getArgument(0),body,null));
        assertThrows(RiskScoringClientException.class,()->client(http).evaluate(request()));
    }

    @Test void invalidJsonDoesNotRetainCredentialBearingParserExcerpts()throws Exception{
        CloseableHttpClient http=mock(CloseableHttpClient.class);
        String body=json("10","LOW","ALLOW","COMPLETE")+" sensitive-parser-canary";
        when(http.execute(any(HttpUriRequest.class))).thenAnswer(call->response(call.getArgument(0),body,null));
        var failure=assertThrows(RiskScoringClientException.class,()->client(http).evaluate(request()));
        assertNull(failure.getCause());assertFalse(failure.toString().contains("sensitive-parser-canary"));
    }

    private static RiskEvaluationRequest request() {
        return new RiskEvaluationRequest("subject-A", "root:tab", "zerotrust-spa", "192.0.2.1", "test", "device-A");
    }

    private static String json(String score, String level, String decision, String status) {
        return """
                {"evaluationId":"11111111-1111-4111-8111-111111111111","subjectId":"subject-A",
                "authenticationSessionId":"root:tab","riskScore":%s,"riskLevel":"%s","decision":"%s",
                "dataStatus":"%s","reasons":[],"evaluatedAt":"2026-11-06T00:00:00Z","trustGeneration":0}
                """.formatted(score, level, decision, status);
    }
}
