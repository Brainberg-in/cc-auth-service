package com.mpsp.cc_auth_service.service;

import com.mpsp.cc_auth_service.dto.LoginResponse;
import com.mpsp.cc_auth_service.dto.SendOtp;
import com.mpsp.cc_auth_service.dto.VerifyOtp;
import org.springframework.stereotype.Component;

@Component
public interface OtpService {
  String sendOtp(String email);

  LoginResponse verifyOtp(String email, String otp);

  boolean validate(String token, VerifyOtp verifyOtp);

  void resendOtp(String email);

  void sendVerificationOtp(String email, SendOtp sendOtp);
}
