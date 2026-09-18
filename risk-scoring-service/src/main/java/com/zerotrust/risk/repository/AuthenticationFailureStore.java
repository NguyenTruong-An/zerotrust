package com.zerotrust.risk.repository;

public interface AuthenticationFailureStore {

    boolean recordFailure(String eventId, String subjectId, String sourceIp);

    long countBySubject(String subjectId);

    long countBySourceIp(String sourceIp);
}
