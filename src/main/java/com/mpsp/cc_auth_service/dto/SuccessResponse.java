package com.mpsp.cc_auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@Getter
@AllArgsConstructor
@ToString
public class SuccessResponse {
  private String status;
  private String message;
}
