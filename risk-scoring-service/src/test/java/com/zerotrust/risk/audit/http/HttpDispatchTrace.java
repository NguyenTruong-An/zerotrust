package com.zerotrust.risk.audit.http;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.List;

/** Observation only: no authentication, exception mapping or transaction wrapper is introduced. */
@TestConfiguration(proxyBeanMethods=false)
class HttpDispatchTrace {
    record Dispatch(String uri, String originalUri, DispatcherType type, Object originalStatus,
                    String exceptionType, boolean transactionAtEntry, int responseStatus) {}
    static final List<Dispatch> RECORDS=new CopyOnWriteArrayList<>();
    @Bean FilterRegistrationBean<Filter> auditDispatchObserver() {
        Filter observer=(request,response,chain)->{
            var req=(HttpServletRequest)request;var res=(HttpServletResponse)response;
            boolean active=org.springframework.transaction.support.TransactionSynchronizationManager.isActualTransactionActive();
            try {chain.doFilter(request,response);} finally {
                Object failure=req.getAttribute(RequestDispatcher.ERROR_EXCEPTION);
                var row=new Dispatch(req.getRequestURI(),(String)req.getAttribute(RequestDispatcher.ERROR_REQUEST_URI),
                        req.getDispatcherType(),req.getAttribute(RequestDispatcher.ERROR_STATUS_CODE),
                        failure==null?null:failure.getClass().getSimpleName(),active,res.getStatus());
                RECORDS.add(row);System.out.println("QA01D DISPATCH "+row);
            }
        };
        var bean=new FilterRegistrationBean<>(observer);bean.setOrder(Integer.MIN_VALUE);
        bean.setDispatcherTypes(DispatcherType.REQUEST,DispatcherType.ERROR);return bean;
    }
}
