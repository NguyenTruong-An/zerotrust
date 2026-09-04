package com.zerotrust.risk;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class RiskScoringApplication {

    public static void main(String[] args) {
        SpringApplication.run(RiskScoringApplication.class, args);
    }
}
