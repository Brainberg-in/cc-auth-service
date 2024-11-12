package com.mpsp.cc_auth_service.service.impl;

import com.mpsp.cc_auth_service.service.AwsService;
import com.mpsp.cc_auth_service.utils.GlobalExceptionHandler;
import com.mpsp.cc_auth_service.utils.ObjectMapperUtils;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.*;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.*;

@Slf4j
@Service
public class AwsServiceImpl implements AwsService {

  @Autowired private transient SesV2Client client;
  @Autowired private transient SnsClient snsClient;

  public void sendEmail(
      final String sender,
      final String recipient,
      final String templateName,
      final Map<String, String> objectMap) {
    final Destination destination = Destination.builder().toAddresses(recipient).build();

    final EmailContent emailContent =
        EmailContent.builder()
            .template(
                Template.builder()
                    .templateName(templateName) // Replace with your template name
                    .templateData(
                        ObjectMapperUtils.dataToJson(objectMap)) // Template data in JSON format
                    .build())
            .build();

    final SendEmailRequest emailRequest =
        SendEmailRequest.builder()
            .destination(destination)
            .content(emailContent)
            .fromEmailAddress(sender)
            .build();

    try {
      log.info("Attempting to send an email of template {} through Amazon SES", templateName);
      client.sendEmail(emailRequest);
    } catch (SesV2Exception e) {
      log.error("Failed to semd {} to {}", templateName, recipient, e);
      throw new GlobalExceptionHandler.SesV2Exception("Failed to send email");
    }
  }

  public void sendSms(
      final String sender,
      final String recipient,
      final String otp) {
    final String destination = "+91" + recipient;

    final PublishRequest smsRequest =
        PublishRequest.builder()
            .message("Your verification code is " + otp)
            .phoneNumber(destination)
            .build();

    try {
      log.info("Attempting to send an sms through Amazon SNS");
      snsClient.publish(smsRequest);
    } catch (SesV2Exception e) {
      log.error("Failed to send SMS to {}", recipient, e);
      throw new GlobalExceptionHandler.SnsException("Failed to send sms");
    }
  }
}
