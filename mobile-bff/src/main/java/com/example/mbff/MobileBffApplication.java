package com.example.mbff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(MobileBffProperties.class)
public class MobileBffApplication {
    public static void main(String[] args) {
        SpringApplication.run(MobileBffApplication.class, args);
    }
}
