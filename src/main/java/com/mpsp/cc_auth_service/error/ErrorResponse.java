package com.mpsp.cc_auth_service.error;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {
  private final String error;
  private String details;
  private Integer remainingAttempts;

  public ErrorResponse(final String error) {
    this.error = error;
  }

  public ErrorResponse(final String error, String details) {
    this.error = error;
    this.details = details;
  }

  public ErrorResponse(final String error, final String details, final Integer remainingAttempts) {
    this.error = error;
    this.details = details;
    this.remainingAttempts = remainingAttempts;
  }
}
