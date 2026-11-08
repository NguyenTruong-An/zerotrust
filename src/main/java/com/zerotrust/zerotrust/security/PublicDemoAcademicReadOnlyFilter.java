package com.zerotrust.zerotrust.security;

import com.zerotrust.zerotrust.config.PublicDemoProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.webmvc.autoconfigure.error.BasicErrorController;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.io.IOException;

/** Runs after JWT and URL authorization; never replaces role or method security. */
public final class PublicDemoAcademicReadOnlyFilter extends OncePerRequestFilter {
    private final PublicDemoProperties properties;
    private final ObjectProvider<RequestMappingHandlerMapping> handlerMapping;

    public PublicDemoAcademicReadOnlyFilter(PublicDemoProperties properties,
            ObjectProvider<RequestMappingHandlerMapping> handlerMapping) {
        this.properties = properties;
        this.handlerMapping = handlerMapping;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        if (properties.enabled() && !isReviewedOperation(request)) {
            throw new AccessDeniedException("Academic API is read-only in Public Demo");
        }
        chain.doFilter(request, response);
    }

    private boolean isReviewedOperation(HttpServletRequest request) throws ServletException {
        try {
            // Resolve the real MVC handler, not a second path-prefix allowlist. New aliases,
            // including side-effecting GET handlers, cannot inherit a read permission by URL.
            HandlerExecutionChain execution = handlerMapping.getObject().getHandler(request);
            if (execution == null || !(execution.getHandler() instanceof HandlerMethod handler)) {
                return false;
            }
            boolean readMethod = "GET".equals(request.getMethod()) || "HEAD".equals(request.getMethod());
            if (BasicErrorController.class.isAssignableFrom(handler.getBeanType())) {
                return readMethod;
            }
            PublicDemoEndpoint endpoint = handler.getMethodAnnotation(PublicDemoEndpoint.class);
            if (endpoint == null) {
                return false;
            }
            return switch (endpoint.value()) {
                case READ -> readMethod;
                // The only current Portal security-state handler is the existing ADMIN MFA reset.
                // Its authorization and lifecycle remain unchanged; D-10 is a separate decision.
                case SECURITY_STATE -> "POST".equals(request.getMethod());
            };
        } catch (HttpRequestMethodNotSupportedException exception) {
            return false;
        } catch (Exception exception) {
            throw new ServletException("Could not classify Public Demo handler", exception);
        }
    }
}
