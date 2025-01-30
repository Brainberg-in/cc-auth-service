package com.mpsp.cc_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.mpsp.cc_auth_service.constants.UserStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@ToString(exclude = {"accessToken", "refreshToken"})
public class LoginResponse {

  @Schema(name = "accessToken", description = "Bearer Token")
  @Setter
  private String accessToken;

  @Schema(name = "refreshToken", description = "Bearer Token")
  private String refreshToken;

  @Setter
  @JsonProperty("isMfaEnabled")
  private boolean mfaEnabled;

  @Setter
  @JsonProperty("isFirstLogin")
  private boolean isFirstLogin;

  private String userRole;

  private String resetToken;

  private UserStatus status;

  public LoginResponse(
      final String accessToken,
      final String refreshToken,
      final boolean mfaEnabled,
      final boolean isFirstLogin,
      final String userRole,
      final UserStatus status) {
    this.mfaEnabled = mfaEnabled;
    this.isFirstLogin = isFirstLogin;
    this.userRole = userRole;
    this.status = status;
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
  }
}
