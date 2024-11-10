package com.mpsp.cc_auth_service.dto;

import com.mpsp.cc_auth_service.dto.validations.ResetPasswordByAdmin;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class UserIdAndRole {
  @NotNull(
      message = "User Id of student or teacher is required",
      groups = ResetPasswordByAdmin.class)
  @Min(value = 1, message = "Invalid User Id", groups = ResetPasswordByAdmin.class)
  private Integer userId;

  @NotNull(message = "User Role is required", groups = ResetPasswordByAdmin.class)
  @Pattern(regexp = "STUDENT|TEACHER", message = "Invalid User Role")
  private String userRole;
}
