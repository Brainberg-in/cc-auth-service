package com.mpsp.cc_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.mpsp.cc_auth_service.constants.UserStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@AllArgsConstructor
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
}
