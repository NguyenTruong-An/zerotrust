package com.zerotrust.risk.service;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(properties={
        "spring.datasource.url=jdbc:h2:mem:postfix03b_timestamp;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE;LOCK_TIMEOUT=20000",
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration"})
@ActiveProfiles("test")
@Import(TimestampLifecyclePrecisionContract.TimeConfig.class)
class TimestampLifecyclePrecisionH2Tests extends TimestampLifecyclePrecisionContract { }
