package com.mpsp.cc_auth_service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ResetPasswordRequest {

  @Schema(description = "User Password")
  @NotBlank(message = "Password is required")
  private String password;

  @Override
  public String toString() {
    return String.format("ResetPasswordRequest[password=%s]", "********");
  }
}
