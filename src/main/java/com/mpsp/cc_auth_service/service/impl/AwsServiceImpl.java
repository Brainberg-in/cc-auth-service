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

@Slf4j
@Service
public class AwsServiceImpl implements AwsService {

  @Autowired private transient SesV2Client client;

  public void sendEmail(
      final String sender,
      final String recipient,
      final String templateName,
      final Map<String, String> objectMap) {
    final Destination destination =
        Destination.builder().toAddresses("sahithi.k@traitfit.com").build();

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
      throw new GlobalExceptionHandler.SesV2Exception(
          String.format("Email not sent for template %s to %s", templateName, recipient));
    }
  }
}
