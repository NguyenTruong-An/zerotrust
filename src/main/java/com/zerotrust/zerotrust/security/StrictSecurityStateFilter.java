package com.zerotrust.zerotrust.security;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
public final class StrictSecurityStateFilter extends OncePerRequestFilter {
    private final StrictSecurityAuthorityClient authority;
    public StrictSecurityStateFilter(StrictSecurityAuthorityClient authority){this.authority=authority;}
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain) throws ServletException,IOException {
        // Validate every authenticated JWT in this chain; encoded API prefixes cannot skip the gate.
        if(!"OPTIONS".equals(request.getMethod())
                && SecurityContextHolder.getContext().getAuthentication() instanceof JwtAuthenticationToken token && token.isAuthenticated()) {
            try{authority.authorize(token.getToken());}
            catch(StrictSecurityAuthorityClient.Rejected failure){error(response,401);return;}
            catch(StrictSecurityAuthorityClient.Unavailable failure){error(response,503);return;}
        }
        chain.doFilter(request,response);
    }
    private void error(HttpServletResponse response,int status)throws IOException {
        response.setStatus(status);response.setContentType("application/json");response.setHeader("Cache-Control","no-store");
        if(status==401)response.setHeader("WWW-Authenticate","Bearer");
        response.getWriter().write("{\"status\":"+status+",\"error\":\""+(status==401?"SECURITY_STATE_REJECTED":"SECURITY_AUTHORITY_UNAVAILABLE")+"\"}");
    }
}
