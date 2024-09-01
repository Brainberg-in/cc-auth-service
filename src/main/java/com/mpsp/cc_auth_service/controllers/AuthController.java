package com.mpsp.cc_auth_service.controllers;

import com.mpsp.cc_auth_service.dto.LoginRequest;
import com.mpsp.cc_auth_service.dto.LoginResponse;
import com.mpsp.cc_auth_service.dto.ResetPasswordRequest;
import com.mpsp.cc_auth_service.service.AuthService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.text.ParseException;
import java.util.Map;
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
  public ResponseEntity<Map<String, String>> logout(
      @RequestHeader(name = HttpHeaders.AUTHORIZATION)
          @NotBlank(message = "Authorization Token is required")
          @Pattern(regexp = "^Bearer\\s", message = "Invalid Authorization")
          final String authorizationHeader)
      throws ParseException {
    authService.logout(authorizationHeader.substring(7));
    return ResponseEntity.ok(Map.of("message", "Logout successful", "status", "success"));
  }

  @PostMapping("/refresh-token")
  public ResponseEntity<LoginResponse> refreshToken(@RequestHeader final String refreshToken)
      throws ParseException {
    return ResponseEntity.ok(authService.refreshToken(refreshToken));
  }

  @PostMapping("/forgot-password")
  public ResponseEntity<Object> forgotPassword(@RequestBody final Map<String, String> request) {
    final String email = request.get("email");

    authService.sendResetPasswordEmail(email);

    return ResponseEntity.ok(Map.of("message", "Reset password email sent.", "status", "success"));
  }

  @PostMapping("/reset-password")
  public ResponseEntity<Object> resetPassword(
      @RequestBody @Valid final ResetPasswordRequest resetPasswordRequest,
      @RequestHeader("Authorization") final String token) {
    try {
      log.info("inside auth controller, inside reset password method");
      authService.resetPassword(resetPasswordRequest, token);
      return ResponseEntity.ok(Map.of("message", "Password reset successfully."));
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired token.");
    }
  }
}
