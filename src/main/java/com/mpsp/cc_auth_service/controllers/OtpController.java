package com.mpsp.cc_auth_service.controllers;

import com.mpsp.cc_auth_service.dto.ResendOtpRequest;
import com.mpsp.cc_auth_service.dto.VerifyOtpRequest;
import com.mpsp.cc_auth_service.service.OtpService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth/otp")
@Validated
public class OtpController {

  @Autowired private OtpService otpService;

  @PostMapping("/validateOtp")
  public ResponseEntity<Object> verifyOtp(
      @RequestBody @Valid VerifyOtpRequest verifyOtpRequest,
      @RequestHeader(name = HttpHeaders.AUTHORIZATION)
          @NotBlank(message = "Authorization Token is required")
          @Pattern(regexp = "^Bearer\\s", message = "Invalid Authorization")
          String token) {
    if (otpService.verifyOtp(token, verifyOtpRequest.getOtp())) {
      Map<String, String> response = new HashMap<>();
      response.put("message", "OTP verified successfully");
      response.put("status", "success");
      return ResponseEntity.ok(response);
    } else {
      Map<String, String> response = new HashMap<>();
      response.put("message", "OTP verification failed");
      response.put("status", "failed");
      return ResponseEntity.badRequest().body(response);
    }
  }

  @PostMapping("/resendOtp")
  public ResponseEntity<Object> resendOtp(@RequestBody @Valid ResendOtpRequest resendOtpRequest) {
    otpService.resendOtp(resendOtpRequest.getEmail());
    Map<String, String> response = new HashMap<>();
    response.put("message", "OTP resent successfully");
    response.put("status", "success");
    return ResponseEntity.ok(response);
  }
}
