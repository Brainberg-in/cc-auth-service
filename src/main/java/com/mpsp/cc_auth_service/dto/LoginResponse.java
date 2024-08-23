package com.mpsp.cc_auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
public class LoginResponse {
  @Setter private String token;
  private String refreshToken;
}
