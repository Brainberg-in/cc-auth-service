package com.mpsp.cc_auth_service.service;

import com.mpsp.cc_auth_service.dto.LoginRequest;
import com.mpsp.cc_auth_service.dto.LoginResponse;
import com.mpsp.cc_auth_service.dto.ResetPasswordRequest;
import com.mpsp.cc_auth_service.dto.UserCreateRequest;
import java.text.ParseException;

public interface AuthService {
  LoginResponse login(LoginRequest loginRequest);

  void logout(String token) throws ParseException;

  LoginResponse refreshToken(String refreshToken);

  void sendResetPasswordEmail(String email);

  void resetPassword(ResetPasswordRequest resetPasswordRequest, String token);

  void createNewUser(UserCreateRequest userCreateRequest);
}
