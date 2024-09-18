package com.mpsp.cc_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@AllArgsConstructor
@Getter
@ToString(exclude = {"accessToken", "refreshToken","roleToken"})
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

  @Schema(name = "roleToken", description = "Bearer Token")
  private String roleToken;

  @JsonProperty("hasMultipleRoles")
  private boolean hasMultipleRoles;
}
