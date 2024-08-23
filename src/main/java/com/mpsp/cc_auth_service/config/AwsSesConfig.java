package com.mpsp.cc_auth_service.config;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AwsSesConfig {

    @Bean
    public SesV2Client amazonSimpleEmailService() {
        return SesV2Client.builder()
                .region(Region.AP_SOUTH_1)
                .build();
    }
}