package com.mpsp.cc_auth_service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

  @Schema(name = "email", example = "johndoe@gmail.com")
  @NotBlank(message = "Email is required")
  @Email(message = "Invalid email")
  private String email;

  @Schema(name = "password", example = "P@ssword123")
  @NotBlank(message = "Password is required")
  private String password;
}
