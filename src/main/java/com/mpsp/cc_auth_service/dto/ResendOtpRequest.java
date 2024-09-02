package com.mpsp.cc_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.mpsp.cc_auth_service.utils.GeneratorUtils;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ResendOtpRequest {

  @NotBlank(message = "Email is required")
  @Email(message = "Invalid email")
  private String email;

  public String toString() {
    return String.format("ResendOtpRequest{email='%s'}", GeneratorUtils.maskEmail(email));
  }
}
