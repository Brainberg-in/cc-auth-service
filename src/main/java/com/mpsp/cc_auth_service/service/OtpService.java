package com.mpsp.cc_auth_service.service;

import org.springframework.stereotype.Component;

import com.mpsp.cc_auth_service.dto.SendOtp;
import com.mpsp.cc_auth_service.dto.VerifyOtp;

@Component
public interface OtpService {
  String sendOtp(String email);

  boolean verifyOtp(String email, String otp);

  boolean validate(String token, VerifyOtp verifyOtp);

  void resendOtp(String email);

  void sendVerificationOtp(String email, SendOtp sendOtp);
}
