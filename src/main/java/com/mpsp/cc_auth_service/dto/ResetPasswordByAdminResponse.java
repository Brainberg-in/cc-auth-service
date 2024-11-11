package com.mpsp.cc_auth_service.dto;

import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ResetPasswordByAdminResponse {
  private Map<Integer, String> failureReasons;
  private String message;
}
