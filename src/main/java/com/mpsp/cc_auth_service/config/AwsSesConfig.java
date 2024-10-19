package com.mpsp.cc_auth_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sesv2.SesV2Client;

@Configuration
public class AwsSesConfig {

  @Bean
  public SesV2Client amazonSimpleEmailService() {
    return SesV2Client.builder()
            .region(Region.AP_SOUTH_1)
            .build();
}
}
