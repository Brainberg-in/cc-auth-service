package com.mpsp.cc_auth_service.controllers;

import com.mpsp.cc_auth_service.service.OtpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/otp")
public class OtpController {

  @Autowired private OtpService otpService;

  @PostMapping("/validateOtp")
  public ResponseEntity<Boolean> verifyOtp(String email, String otp) {
    return ResponseEntity.ok(otpService.verifyOtp(email, otp));
  }

  @PostMapping("/resend")
  public ResponseEntity<String> resendOtp(String email) {
    otpService.resendOtp(email);
    return ResponseEntity.ok("OTP resent successfully");
  }
}
