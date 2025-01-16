package com.mpsp.cc_auth_service.controllers;

import com.mpsp.cc_auth_service.dto.ApiResponse;
import com.mpsp.cc_auth_service.dto.SendOtp;
import com.mpsp.cc_auth_service.dto.VerifyOtp;
import com.mpsp.cc_auth_service.dto.VerifyOtpRequest;
import com.mpsp.cc_auth_service.service.OtpService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
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
  public ResponseEntity<ApiResponse> verifyOtp(
      @RequestBody @Valid VerifyOtpRequest verifyOtpRequest,
      @RequestHeader(name = HttpHeaders.AUTHORIZATION)
          @NotBlank(message = "Authorization Token is required")
          @Pattern(regexp = "^Bearer .+$", message = "Invalid Authorization")
          String token) {
    otpService.verifyOtp(token, verifyOtpRequest.getOtp());
    return ResponseEntity.ok(new ApiResponse("OTP verified successfully"));
  }

  @PostMapping("/validate")
  public ResponseEntity<ApiResponse> validate(
      @RequestBody @Valid VerifyOtp verifyOtpRequest,
      @RequestHeader(name = HttpHeaders.AUTHORIZATION)
          @NotBlank(message = "Authorization Token is required")
          @Pattern(regexp = "^Bearer .+$", message = "Invalid Authorization")
          String token) {
    otpService.validate(token, verifyOtpRequest);
    return ResponseEntity.ok(new ApiResponse("OTP verified successfully"));
  }

  @PostMapping("/resendOtp")
  public ResponseEntity<ApiResponse> resendOtp(
      @RequestHeader(name = HttpHeaders.AUTHORIZATION)
          @NotBlank(message = "Authorization Token is required")
          @Pattern(regexp = "^Bearer .+$", message = "Invalid Authorization")
          String token) {
    otpService.resendOtp(token);
    return ResponseEntity.ok(new ApiResponse("OTP resent successfully"));
  }

  @PostMapping("/send")
  public ResponseEntity<ApiResponse> sendVerificationOtp(
      @RequestHeader(name = HttpHeaders.AUTHORIZATION)
          @NotBlank(message = "Authorization Token is required")
          @Pattern(regexp = "^Bearer .+$", message = "Invalid Authorization")
          String token,
      @RequestBody @Valid SendOtp sendOtp) {
    otpService.sendVerificationOtp(token, sendOtp);
    return ResponseEntity.ok(new ApiResponse("OTP sent successfully"));
  }
}
