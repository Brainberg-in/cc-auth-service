package com.mpsp.cc_auth_service.service.impl;

import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.amazonaws.services.simpleemail.model.*;
import com.mpsp.cc_auth_service.service.AwsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AwsServiceImpl implements AwsService{
        @Autowired
    private AmazonSimpleEmailService amazonSimpleEmailService;

    public void sendEmail(String toAddress, String subject, String body) {
        SendEmailRequest sendEmailRequest = new SendEmailRequest()
                .withDestination(new Destination().withToAddresses(toAddress))
                .withMessage(new Message()
                        .withBody(new Body()
                                .withHtml(new Content()
                                        .withCharset("UTF-8")
                                        .withData(body))
                                .withText(new Content()
                                        .withCharset("UTF-8")
                                        .withData(body)))
                        .withSubject(new Content()
                                .withCharset("UTF-8")
                                .withData(subject)))
                .withSource("your-email@example.com"); // Replace with your verified SES email address

        SendEmailResult result = amazonSimpleEmailService.sendEmail(sendEmailRequest);
        System.out.println("Email sent with Message ID: " + result.getMessageId());
    }
}
