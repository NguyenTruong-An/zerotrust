package com.zerotrust.risk.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.Collections;

/** Transport-attempt correlation after authorization; not authentication or a scoring input. */
public final class RiskEvaluationCorrelationFilter extends OncePerRequestFilter {
    public static final String HEADER = "X-ZeroTrust-Risk-Request";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if ("POST".equals(request.getMethod()) && (request.getContextPath() + "/internal/v1/risk/evaluations")
                .equals(request.getRequestURI())) {
            var values = Collections.list(request.getHeaders(HEADER));
            // Existing internal callers remain compatible; the hardened SPI always requires the echo.
            if (!values.isEmpty()) {
                if (values.size() != 1 || !values.get(0).matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")) {
                    response.setStatus(400);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"status\":400,\"error\":\"INVALID_RISK_REQUEST_CORRELATION\"}");
                    return;
                }
                response.setHeader(HEADER, values.get(0));
            }
        }
        chain.doFilter(request, response);
    }
}
