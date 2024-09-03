package com.mpsp.cc_auth_service.error;

import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class ErrorResponse {
  private final String error;
  private final String status;

  public ErrorResponse(final String error) {
    this.error = error;
    this.status = "failed";
  }
}
