package com.mpsp.cc_auth_service.dto;


import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
public class VerifyOtpRequest {

  @NotBlank(message = "Otp is Required")
  @Size(min = 4, max = 4, message = "Otp must be 4 characters")
  @Pattern(regexp = "^[0-9]*$", message = "Invalid Otp")
  private String otp;
}
