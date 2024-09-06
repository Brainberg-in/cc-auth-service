package com.mpsp.cc_auth_service.pojo;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.mpsp.cc_auth_service.error.ErrorResponse;
import org.junit.jupiter.api.Test;

public class ErrorResponseTest {

  @Test
  public void testErrorResponse() {
    final ErrorResponse errorResponse = new ErrorResponse("Invalid Credentials");
    assertEquals("Invalid Credentials", errorResponse.getError());
    assertEquals("failed", errorResponse.getStatus());
    assertEquals(
        "ErrorResponse(error=Invalid Credentials, status=failed)", errorResponse.toString());
  }
}
