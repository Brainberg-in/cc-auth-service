package com.mpsp.cc_auth_service.service;

public interface AwsService {
    void sendEmail(String sender,
                   String recipient,
                   String subject,
                   String bodyHTML);
}
