package com.mpsp.cc_auth_service.dto;

import com.mpsp.cc_auth_service.dto.validations.ResetPasswordByAdmin;
import com.mpsp.cc_auth_service.dto.validations.ResetPasswordSelf;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ResetPasswordRequest {

  @Schema(description = "User Password")
  @NotBlank(
      message = "Password is required",
      groups = {ResetPasswordSelf.class})
  private String password;

  @Schema(description = "Reset Token")
  @NotBlank(
      message = "Reset Token is required",
      groups = {ResetPasswordSelf.class})
  private String resetToken;

  @NotEmpty(message = "Atleast ", groups = ResetPasswordByAdmin.class)
  private List<UserIdAndRole> behalfOf;

  @Override
  public String toString() {
    return String.format("ResetPasswordRequest[password=%s]", "********");
  }
}
