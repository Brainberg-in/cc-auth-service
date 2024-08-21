package com.mpsp.cc_auth_service.service;

public interface AwsService {
    void sendEmail(String email, String subject, String body);
}
