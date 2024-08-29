package com.mpsp.cc_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
public class LoginResponse {

  @Schema(name = "token", description = "Bearer Token")
  @Setter
  private String token;

  @Schema(name = "refreshToken", description = "Bearer Token")
  private String refreshToken;

  @Setter
  @JsonProperty("isMfaEnabled")
  private boolean isMfaEnabled;

  @JsonProperty("isFirstLogin")
  private boolean isFirstLogin;
}
