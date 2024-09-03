package com.mpsp.cc_auth_service.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sesv2.SesV2Client;

@Configuration
public class AwsSesConfig {

  @Value("${aws.ses.key}")
  private String sesKey;

  @Value("${aws.ses.secret}")
  private String sesSecret;

  @Bean
  public SesV2Client amazonSimpleEmailService() {
    final AwsBasicCredentials awsBasicCredentials = AwsBasicCredentials.create(sesKey, sesSecret);

    return SesV2Client.builder()
        .region(Region.AP_SOUTH_1)
        .credentialsProvider(StaticCredentialsProvider.create(awsBasicCredentials))
        .build();
  }
}
