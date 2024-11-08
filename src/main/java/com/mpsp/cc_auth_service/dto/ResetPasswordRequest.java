package com.mpsp.cc_auth_service.dto;

import com.mpsp.cc_auth_service.dto.validations.ResetPasswordByAdmin;
import com.mpsp.cc_auth_service.dto.validations.ResetPasswordSelf;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ResetPasswordRequest {

  @Schema(description = "User Password")
  @NotBlank(
      message = "Password is required",
      groups = {ResetPasswordByAdmin.class, ResetPasswordSelf.class})
  private String password;

  @Schema(description = "Reset Token")
  @NotBlank(
      message = "Reset Token is required",
      groups = {ResetPasswordSelf.class})
  private String resetToken;

  @NotBlank(message = "User Role is required", groups = ResetPasswordByAdmin.class)
  @Pattern(regexp = "STUDENT|TEACHER", message = "Invalid User Role")
  private String behalfOfUserRole;

  @NotNull(
      message = "User Id of student or teacher is required",
      groups = ResetPasswordByAdmin.class)
  @Min(value = 1, message = "Invalid User Id", groups = ResetPasswordByAdmin.class)
  private Integer behalfOf;

  @Override
  public String toString() {
    return String.format("ResetPasswordRequest[password=%s]", "********");
  }
}
