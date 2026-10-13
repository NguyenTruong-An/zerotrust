package com.zerotrust.risk.audit.http;

import com.zerotrust.risk.entity.DeviceStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

@EnabledIfSystemProperty(named="qa.http.audit",matches="true")
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class RiskSubjectHttpRegressionTests extends HttpAuditSupport {
    @ParameterizedTest @ValueSource(strings={"canonical","padded","uppercase","opaque"})
    void stringRegistrationEvaluationAndGenerationUseTheSameSubject(String form) throws Exception {
        String s=id();if(form.equals("uppercase"))s=s.toUpperCase(Locale.ROOT);if(form.equals("opaque"))s="f:qa-component:"+s;
        String submitted=form.equals("padded")?" \t"+s+"\r\n ":s;
        history(s,6);trusted(submitted);
        for(String input:List.of(s,submitted)) {
            var response=post(EVAL,allowed(EVAL),evaluation(input,"10.1.2.3"));assertThat(response.statusCode()).isEqualTo(200);
            var result=node(response);assertThat(result.path("subjectId").asText()).isEqualTo(input);
            assertThat(result.path("decision").asText()).isEqualTo("ALLOW");assertThat(result.path("dataStatus").asText()).isEqualTo("COMPLETE");
            assertThat(result.path("riskScore").decimalValue()).isEqualByComparingTo("0");assertThat(result.path("trustGeneration").asLong()).isZero();
        }
        assertThat(devices.findAllBySubjectId(s)).hasSize(1);
    }
    @Test void uuidPathResetAndCompletionFenceStringAliasesWithoutAResetBypass() throws Exception {
        String s=id(),padded=" "+s+" ",path=revoke("%20"+s+"%20"),op=id(),payload=operation(op,"qa-admin");
        history(s,6);trusted(padded);
        assertThat(post(path,allowed(path),payload).statusCode()).isEqualTo(204);
        assertThat(devices.findAllBySubjectId(s).get(0).getStatus()).isEqualTo(DeviceStatus.REVOKED);
        assertThat(lifecycle.snapshot(padded)).isEqualTo(new com.zerotrust.risk.service.DeviceTrustLifecycle.Snapshot(1,true));
        assertThat(post(REG,allowed(REG),reg(padded,1)).statusCode()).isEqualTo(409);
        assertThat(post(path+"/completion",allowed(path),payload).statusCode()).isEqualTo(204);
        var result=node(post(EVAL,allowed(EVAL),evaluation(padded,"10.1.2.3")));
        assertThat(result.path("decision").asText()).isEqualTo("STEP_UP_MFA");assertThat(result.path("trustGeneration").asLong()).isEqualTo(1);
        assertThat(lifecycle.snapshot(s).resetPending()).isFalse();
        assertThat(post(REG,allowed(REG),reg(padded,0)).statusCode()).isEqualTo(409);
    }
    @ParameterizedTest @NullAndEmptySource @ValueSource(strings={" ","\t\r\n"})
    void invalidStringSubjectsRemain400WithoutMutation(String input) throws Exception {
        invalidString(input);
    }
    @Test void overlongStringSubjectRemains400WithoutMutation() throws Exception {invalidString("x".repeat(256));}
    void invalidString(String input) throws Exception {
        var before=db();var registrationBody=new HashMap<String,Object>();registrationBody.put("subjectId",input);registrationBody.put("deviceId",DEVICE);registrationBody.put("trustGeneration",0);
        var evaluationBody=new HashMap<String,Object>(Map.of("authenticationSessionId","session","clientId",CLIENT,"ipAddress","10.1.2.3","deviceId",DEVICE));evaluationBody.put("subjectId",input);
        for(var b:List.of(Map.entry(REG,registrationBody),Map.entry(EVAL,evaluationBody))){var response=post(b.getKey(),allowed(b.getKey()),json(b.getValue()));assertThat(response.statusCode()).isEqualTo(400);assertThat(node(response).path("fieldErrors").has("subjectId")).isTrue();}
        unchanged(before);
    }
    @Test void opaqueStringIsAcceptedByStringApiButRejectedByUuidResetPath() throws Exception {
        String s="not-a-uuid-"+id();trusted(s);var before=db();String path=revoke(s);
        assertThat(post(path,allowed(path),operation(id(),"qa-admin")).statusCode()).isEqualTo(400);
        unchanged(before);
    }
    @Test void differentUserCannotInheritTheSameDeviceCookieTrust() throws Exception {
        String a=id(),b=id();history(a,6);history(b,6);trusted(" "+a+" ");
        var result=node(post(EVAL,allowed(EVAL),evaluation(" "+b+" ","10.1.2.3")));
        assertThat(result.path("decision").asText()).isEqualTo("STEP_UP_MFA");assertThat(result.path("reasons").toString()).contains("NEW_DEVICE");
        assertThat(devices.findAllBySubjectId(b)).isEmpty();
    }
    @Test void wrongCallerOrRoleStillCannotRegisterOrRevoke() throws Exception {
        String s=id();var before=db();String path=revoke(s);
        assertThat(post(REG,HttpJwtFixture.token(HttpJwtFixture.CALLER,"risk:evaluate"),reg(s,0)).statusCode()).isEqualTo(403);
        assertThat(post(path,HttpJwtFixture.token(HttpJwtFixture.CALLER,"risk:device:revoke"),operation(id(),"qa-admin")).statusCode()).isEqualTo(403);
        unchanged(before);
    }
}
