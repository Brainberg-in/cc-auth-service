package com.mpsp.cc_auth_service.service;

import com.mpsp.cc_auth_service.dto.LoginRequest;
import com.mpsp.cc_auth_service.dto.LoginResponse;

import java.text.ParseException;

public interface AuthService {
  LoginResponse login(LoginRequest loginRequest);

  void logout(String token) throws ParseException;

  LoginResponse refreshToken(String refreshToken) throws ParseException;
}
