package com.mpsp.cc_auth_service.controllers;

import com.mpsp.cc_auth_service.dto.LoginRequest;
import com.mpsp.cc_auth_service.dto.LoginResponse;
import com.mpsp.cc_auth_service.dto.ResetPasswordRequest;
import com.mpsp.cc_auth_service.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@Slf4j
public class AuthController {

  @Autowired private AuthService authService;

  @PostMapping("/login")
  public ResponseEntity<LoginResponse> login(@RequestBody @Valid final LoginRequest loginRequest) {
    LoginResponse loginResponse = authService.login(loginRequest);
    return ResponseEntity.ok(loginResponse);
  }

  @PostMapping("/logout")
  public ResponseEntity<Object> logout(HttpServletRequest request) throws ParseException {
    String authorizationHeader = request.getHeader("Authorization");

    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
      String token = authorizationHeader.substring(7);
      authService.logout(token);
      Map<String, String> response = new HashMap<>();
      response.put("message", "Logout successfull");
      response.put("status", "success");
      return ResponseEntity.ok(response);
    }
    return ResponseEntity.badRequest().body("Invalid Authorization");
  }
  @PostMapping("/refresh-token")
  public ResponseEntity<LoginResponse> refreshToken(
      @RequestHeader final String refreshToken) throws ParseException {
    LoginResponse loginResponse = authService.refreshToken(refreshToken);
    return ResponseEntity.ok(loginResponse);
  }
  @PostMapping("/forgot-password")
  public ResponseEntity<Object> forgotPassword(@RequestBody Map<String, String> request) {
    String email = request.get("email");

    authService.sendResetPasswordEmail(email);
    Map<String, String> response = new HashMap<>();
    response.put("message", "Reset password email sent.");
    response.put("status", "success");

    return ResponseEntity.ok(response);

  }

  @PostMapping("/reset-password")
  public ResponseEntity<Object> resetPassword(@RequestBody @Valid ResetPasswordRequest resetPasswordRequest, @RequestHeader("Authorization") String token) {
    try {
        log.info("inside auth controller, inside reset password method");
        authService.resetPassword(resetPasswordRequest,token);
        return ResponseEntity.ok(Map.of("message","Password reset successfully."));
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired token.");
    }
  }
}
