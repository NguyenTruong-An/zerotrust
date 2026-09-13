package com.zerotrust.risk.security;

import com.zerotrust.risk.config.RiskApiSecurityConfig;
import com.zerotrust.risk.config.RiskApiSecurityProperties;
import com.zerotrust.risk.controller.RiskEvaluationController;
import com.zerotrust.risk.service.RiskEvaluationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(
        controllers = RiskEvaluationController.class,
        properties = {
                "risk.security.issuer-uri=https://keycloak.example/realms/DoAn",
                "risk.security.jwk-set-uri=https://keycloak.example/realms/DoAn/protocol/openid-connect/certs",
                "risk.security.audience=zerotrust-risk-api",
                "risk.security.allowed-client-id=zerotrust-risk-caller",
                "risk.security.require-https=true"
        }
)
@Import(RiskApiSecurityConfig.class)
@EnableConfigurationProperties(RiskApiSecurityProperties.class)
class RiskApiHttpsSecurityTests {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private RiskEvaluationService riskEvaluationService;

    @Test
    void refusesPlainHttpBeforeAuthenticationOrControllerExecution() throws Exception {
        mockMvc.perform(post("/internal/v1/risk/evaluations")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("HTTPS_REQUIRED"));

        verify(riskEvaluationService, never()).evaluate(any());
    }
}
