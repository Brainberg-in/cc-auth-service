package com.mpsp.cc_auth_service.service;

import com.mpsp.cc_auth_service.dto.LoginRequest;
import com.mpsp.cc_auth_service.dto.LoginResponse;

public interface AuthService {
  LoginResponse login(LoginRequest loginRequest);

  void logout(Integer userId);

  LoginResponse refreshToken(String refreshToken);
}
