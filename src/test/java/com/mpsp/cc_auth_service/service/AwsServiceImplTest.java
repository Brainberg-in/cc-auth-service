package com.mpsp.cc_auth_service.service;

import static org.mockito.Mockito.*;

import com.mpsp.cc_auth_service.service.impl.AwsServiceImpl;
import com.mpsp.cc_auth_service.utils.ObjectMapperUtils;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.*;

@ExtendWith(MockitoExtension.class)
public class AwsServiceImplTest {

  @InjectMocks private AwsServiceImpl awsService;

  @Mock private SesV2Client client;

  @BeforeEach
  public void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  public void testSendEmail_Success() {
    String sender = "sender@example.com";
    String recipient = "recipient@example.com";
    String templateName = "templateName";
    Map<String, String> objectMap = Map.of("key", "value");

    SendEmailRequest emailRequest =
        SendEmailRequest.builder()
            .destination(Destination.builder().toAddresses(recipient).build())
            .content(
                EmailContent.builder()
                    .template(
                        Template.builder()
                            .templateName(templateName)
                            .templateData(ObjectMapperUtils.dataToJson(objectMap))
                            .build())
                    .build())
            .fromEmailAddress(sender)
            .build();
    awsService.sendEmail(sender, recipient, templateName, objectMap);
    verify(client, times(1)).sendEmail(any(SendEmailRequest.class));
  }
}
