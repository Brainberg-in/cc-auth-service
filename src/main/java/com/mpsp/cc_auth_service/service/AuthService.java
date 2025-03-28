package com.mpsp.cc_auth_service.service;

import com.mpsp.cc_auth_service.dto.*;
import java.util.List;
import java.util.Map;

public interface AuthService {
  LoginResponse login(LoginRequest loginRequest, String ipAddress);

  void logout(String token);

  LoginResponse refreshToken(String refreshToken);

  void sendResetPasswordEmail(String email);

  void changePassword(ChangePasswordRequest changePasswordRequest, String token);

  void createNewUser(UserCreateRequest userCreateRequest);

  void resetPasswordSelf(ResetPasswordRequest resetPasswordRequest);

  ResetPasswordByAdminResponse resetPasswordByAdmin(
      ResetPasswordRequest resetPasswordRequest, String token);

  Map<Integer, String> getUserRoles(List<Integer> userIds);

  List<LoginHistoryResponse> getLoginHistory(Integer userId);
}
