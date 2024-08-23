package com.mpsp.cc_auth_service.service.impl;

import com.mpsp.cc_auth_service.service.AwsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.Body;
import software.amazon.awssdk.services.sesv2.model.Content;
import software.amazon.awssdk.services.sesv2.model.Destination;
import software.amazon.awssdk.services.sesv2.model.EmailContent;
import software.amazon.awssdk.services.sesv2.model.Message;
import software.amazon.awssdk.services.sesv2.model.SendEmailRequest;
import software.amazon.awssdk.services.sesv2.model.SesV2Exception;

@Slf4j
@Service
public class AwsServiceImpl implements AwsService {

  @Autowired private SesV2Client client;

  public void sendEmail(
      final String sender, final String recipient, final String subject, final String bodyHTML) {

    final Destination destination = Destination.builder().toAddresses(recipient).build();

    final Content content = Content.builder().data(bodyHTML).build();

    final Content sub = Content.builder().data(subject).build();

    final Body body = Body.builder().html(content).build();

    final Message msg = Message.builder().subject(sub).body(body).build();

    final EmailContent emailContent = EmailContent.builder().simple(msg).build();

    final SendEmailRequest emailRequest =
        SendEmailRequest.builder()
            .destination(destination)
            .content(emailContent)
            .fromEmailAddress(sender)
            .build();

    try {
      log.info("Attempting to send an email through Amazon SES ");
      client.sendEmail(emailRequest);
      log.info("email was sent");

    } catch (SesV2Exception e) {
      log.error("Failed to send email", e);
    }
  }
}
