package com.mpsp.cc_auth_service.error;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {
  private final String error;
  private String details;

  public ErrorResponse(String error) {
    this.error = error;
  }

  public ErrorResponse(String error, String details) {
    this.error = error;
    this.details = details;
  }
}
