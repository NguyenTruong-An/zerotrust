package com.zerotrust.zerotrust;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients
public class ZerotrustApplication {
    public static void main(String[] args) {
        SpringApplication.run(ZerotrustApplication.class, args);
    }

}
