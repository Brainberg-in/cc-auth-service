package com.mpsp.cc_auth_service.controllers;

import com.mpsp.cc_auth_service.dto.LoginRequest;
import com.mpsp.cc_auth_service.dto.LoginResponse;
import com.mpsp.cc_auth_service.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

  @Autowired private AuthService authService;

  @PostMapping("/login")
  public ResponseEntity<LoginResponse> login(@RequestBody @Valid final LoginRequest loginRequest) {
    LoginResponse loginResponse = authService.login(loginRequest);
    return ResponseEntity.ok(loginResponse);
  }

  @PostMapping("/logout")
  public ResponseEntity<String> logout(HttpServletRequest request) throws ParseException {
    String authorizationHeader = request.getHeader("Authorization");

    // Check if the Authorization header is present and starts with "Bearer "
    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
      // Extract the token
      String token = authorizationHeader.substring(7);
      authService.logout(token);
      return ResponseEntity.ok("Logout successful");
    }
    return ResponseEntity.badRequest().body("Invalid Authorization");
  }
  @PostMapping("/refresh-token")
  public ResponseEntity<LoginResponse> refreshToken(
      @RequestHeader final String refreshToken) throws ParseException {
    LoginResponse loginResponse = authService.refreshToken(refreshToken);
    return ResponseEntity.ok(loginResponse);
  }
}
