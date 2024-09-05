package com.mpsp.cc_auth_service.controllers;

import com.mpsp.cc_auth_service.dto.ResendOtpRequest;
import com.mpsp.cc_auth_service.dto.VerifyOtpRequest;
import com.mpsp.cc_auth_service.service.OtpService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth/otp")
@Validated
public class OtpController {

  @Autowired private OtpService otpService;

  @PostMapping("/validateOtp")
  public ResponseEntity<String> verifyOtp(
      @RequestBody @Valid VerifyOtpRequest verifyOtpRequest,
      @RequestHeader(name = HttpHeaders.AUTHORIZATION)
          @NotBlank(message = "Authorization Token is required")
          @Pattern(regexp = "^Bearer .+$", message = "Invalid Authorization")
          String token) {
    if (otpService.verifyOtp(token, verifyOtpRequest.getOtp())) {
      return ResponseEntity.ok("OTP verified successfully");
    } else {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("OTP verification failed");
    }
  }

  @PostMapping("/resendOtp")
  public ResponseEntity<String> resendOtp(
      @RequestBody @Valid ResendOtpRequest resendOtpRequest, @RequestHeader(name = HttpHeaders.AUTHORIZATION)
      @NotBlank(message = "Authorization Token is required")
      @Pattern(regexp = "^Bearer .+$", message = "Invalid Authorization")
      String token) {
    otpService.resendOtp(token);
    return ResponseEntity.ok("OTP resent successfully");
  }
}
