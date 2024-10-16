package com.mpsp.cc_auth_service.service;

import java.util.List;
import java.util.Map;
import com.mpsp.cc_auth_service.dto.*;

public interface AuthService {
  LoginResponse login(LoginRequest loginRequest);

  void logout(String token);

  LoginResponse refreshToken(String refreshToken);

  void sendResetPasswordEmail(String email);

  void changePassword(ChangePasswordRequest changePasswordRequest, String token);

  void createNewUser(UserCreateRequest userCreateRequest);

  void resetPassword(ResetPasswordRequest resetPasswordRequest);

  Map<Integer, String> getUserRoles(List<Integer> userIds);
}
