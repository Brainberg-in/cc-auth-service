package com.mpsp.cc_auth_service.pojo;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mpsp.cc_auth_service.error.ErrorResponse;
import org.junit.jupiter.api.Test;

class ErrorResponseTest {

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Test
  void constructor_WithErrorOnly_ShouldSetErrorField() {
    // Given
    String error = "Test error";

    // When
    ErrorResponse response = new ErrorResponse(error);

    // Then
    assertEquals(error, response.getError());
    assertNull(response.getDetails());
    assertNull(response.getRemainingAttempts());
  }

  @Test
  void constructor_WithErrorAndDetails_ShouldSetBothFields() {
    // Given
    String error = "Test error";
    String details = "Test details";

    // When
    ErrorResponse response = new ErrorResponse(error, details);

    // Then
    assertEquals(error, response.getError());
    assertEquals(details, response.getDetails());
    assertNull(response.getRemainingAttempts());
  }

  @Test
  void constructor_WithAllFields_ShouldSetAllFields() {
    // Given
    String error = "Test error";
    String details = "Test details";
    Integer attempts = 3;

    // When
    ErrorResponse response = new ErrorResponse(error, details, attempts);

    // Then
    assertEquals(error, response.getError());
    assertEquals(details, response.getDetails());
    assertEquals(attempts, response.getRemainingAttempts());
  }

  @Test
  void jsonSerialization_WithAllFields_ShouldIncludeAllFields() throws Exception {
    // Given
    ErrorResponse response = new ErrorResponse("Test error", "Test details", 3);

    // When
    String json = objectMapper.writeValueAsString(response);

    // Then
    assertTrue(json.contains("\"error\":\"Test error\""));
    assertTrue(json.contains("\"details\":\"Test details\""));
    assertTrue(json.contains("\"remainingAttempts\":3"));
  }

  @Test
  void jsonSerialization_WithNullFields_ShouldOmitNullFields() throws Exception {
    // Given
    ErrorResponse response = new ErrorResponse("Test error");

    // When
    String json = objectMapper.writeValueAsString(response);

    // Then
    assertTrue(json.contains("\"error\":\"Test error\""));
    assertFalse(json.contains("\"details\""));
    assertFalse(json.contains("\"remainingAttempts\""));
  }

  @Test
  void equals_WithSameValues_ShouldBeEqual() {
    // Given
    ErrorResponse response1 = new ErrorResponse("error", "details", 3);
    ErrorResponse response2 = new ErrorResponse("error", "details", 3);

    // Then
    assertEquals(response1, response2);
    assertEquals(response1.hashCode(), response2.hashCode());
  }

  @Test
  void equals_WithDifferentValues_ShouldNotBeEqual() {
    // Given
    ErrorResponse response1 = new ErrorResponse("error1", "details", 3);
    ErrorResponse response2 = new ErrorResponse("error2", "details", 3);

    // Then
    assertNotEquals(response1, response2);
  }

  @Test
  void toString_ShouldContainAllFields() {
    // Given
    ErrorResponse response = new ErrorResponse("Test error", "Test details", 3);

    // When
    String toString = response.toString();

    // Then
    assertTrue(toString.contains("error=Test error"));
    assertTrue(toString.contains("details=Test details"));
    assertTrue(toString.contains("remainingAttempts=3"));
  }

  @Test
  void setters_ShouldModifyFields() {
    // Given
    ErrorResponse response = new ErrorResponse("Initial error");

    // When
    response.setDetails("New details");
    response.setRemainingAttempts(5);

    // Then
    assertEquals("Initial error", response.getError());
    assertEquals("New details", response.getDetails());
    assertEquals(5, response.getRemainingAttempts());
  }

  @Test
  void constructor_WithNullValues_ShouldAcceptNulls() {
    // When
    ErrorResponse response = new ErrorResponse(null, null, null);

    // Then
    assertNull(response.getError());
    assertNull(response.getDetails());
    assertNull(response.getRemainingAttempts());
  }
}
