package com.mpsp.cc_auth_service.service;

import org.springframework.stereotype.Component;


@Component
public interface OtpService {
    String sendOtp(String email);

    boolean verifyOtp(String email, String otp);

    void resendOtp(String email);
}
