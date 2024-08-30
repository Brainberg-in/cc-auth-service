package com.mpsp.cc_auth_service.controllers;

import com.mpsp.cc_auth_service.dto.ResendOtpRequest;
import com.mpsp.cc_auth_service.dto.VerifyOtpRequest;
import com.mpsp.cc_auth_service.service.OtpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping("/api/v1/auth/otp")
public class OtpController {

  @Autowired private OtpService otpService;

  @PostMapping("/validateOtp")
  public ResponseEntity<Object> verifyOtp(@RequestBody VerifyOtpRequest verifyOtpRequest, @RequestHeader("Authorization") String token) {
    if(otpService.verifyOtp(token, verifyOtpRequest.getOtp())){
      Map<String, String> response = new HashMap<>();
      response.put("message", "OTP verified successfully");
      response.put("status", "success");
      return ResponseEntity.ok(response);
    }else{
        Map<String, String> response = new HashMap<>();
        response.put("message", "OTP verification failed");
        response.put("status", "failed");
        return ResponseEntity.badRequest().body(response);
    }
  }

  @PostMapping("/resendOtp")
  public ResponseEntity<Object> resendOtp(@RequestBody ResendOtpRequest resendOtpRequest) {
    otpService.resendOtp(resendOtpRequest.getEmail());
    Map<String, String> response = new HashMap<>();
    response.put("message", "OTP resent successfully");
    response.put("status", "success");
    return ResponseEntity.ok(response);
  }
}
