package com.mpsp.cc_auth_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.SnsClient;

@Configuration
public class AwsSnsConfig {

    @Bean
    public SnsClient amazonSimpleNotificationService() {
        return SnsClient.builder().region(Region.AP_SOUTH_1).build();
    }
}
