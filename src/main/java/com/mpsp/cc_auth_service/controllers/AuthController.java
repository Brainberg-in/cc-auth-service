package com.mpsp.cc_auth_service.controllers;

import com.mpsp.cc_auth_service.constants.AppConstants;
import com.mpsp.cc_auth_service.dto.*;
import com.mpsp.cc_auth_service.service.AuthService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.text.ParseException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@Slf4j
@Validated
public class AuthController {

  @Autowired private AuthService authService;

  @PostMapping("/login")
  public ResponseEntity<LoginResponse> login(@RequestBody @Valid final LoginRequest loginRequest) {
    return ResponseEntity.ok(authService.login(loginRequest));
  }

  @PostMapping("/logout")
  public ResponseEntity<ApiResponse> logout(
      @RequestHeader(name = HttpHeaders.AUTHORIZATION)
          @NotBlank(message = "Authorization Token is required")
          @Pattern(regexp = "^Bearer .+$", message = "Invalid Authorization Token")
          final String authorizationHeader)
      throws ParseException {
    authService.logout(authorizationHeader.substring(AppConstants.BEARER.length()));
    return ResponseEntity.ok(new ApiResponse("Logout successful"));
  }

  @PostMapping("/refresh-token")
  public ResponseEntity<LoginResponse> refreshToken(
      @RequestHeader("refreshToken") @NotBlank(message = "Refresh Token is required")
          final String refreshToken) {
    return ResponseEntity.ok(authService.refreshToken(refreshToken));
  }

  @PostMapping("/forgot-password")
  public ResponseEntity<ApiResponse> forgotPassword(
      @RequestBody @Valid final ResendOtpRequest request) {
    final String email = request.getEmail();

    authService.sendResetPasswordEmail(email);

    return ResponseEntity.ok(
        new ApiResponse("A link to reset your password has been sent to your email."));
  }

  @PostMapping("/reset-password")
  public ResponseEntity<ApiResponse> resetPassword(
      @RequestBody @Valid final ResetPasswordRequest resetPasswordRequest) {
    authService.resetPassword(resetPasswordRequest);
    return ResponseEntity.ok(new ApiResponse("Password reset successfully."));
  }

  @PostMapping("/change-password")
  public ResponseEntity<ApiResponse> changePassword(
      @RequestBody @Valid final ChangePasswordRequest changePasswordRequest,
      @RequestHeader(HttpHeaders.AUTHORIZATION)
          @Pattern(regexp = "^Bearer .+$", message = "Invalid Authorization Token")
          final String token) {
    authService.changePassword(changePasswordRequest, token);
    return ResponseEntity.ok(new ApiResponse("Password changed successfully."));
  }

  @PostMapping("/create-user")
  public ResponseEntity<Void> createNewUser(
      @RequestBody @Valid final UserCreateRequest userCreateRequest) {
    authService.createNewUser(userCreateRequest);
    return ResponseEntity.status(HttpStatus.CREATED).build();
  }
}
