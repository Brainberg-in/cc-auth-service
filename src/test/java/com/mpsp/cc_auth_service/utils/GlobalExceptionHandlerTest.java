package com.mpsp.cc_auth_service.utils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.mpsp.cc_auth_service.error.ErrorResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.context.request.WebRequest;

public class GlobalExceptionHandlerTest {

  private GlobalExceptionHandler exceptionHandler;
  private WebRequest webRequest;
  private HttpHeaders headers;

  @BeforeEach
  void setUp() {
    exceptionHandler = new GlobalExceptionHandler();
    webRequest = mock(WebRequest.class);
    headers = new HttpHeaders();
  }

  @Test
  void handleMethodArgumentNotValid() {
    MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
    BindingResult bindingResult = mock(BindingResult.class);
    List<FieldError> fieldErrors = new ArrayList<>();
    FieldError error = new FieldError("object", "field", "Error message");
    fieldErrors.add(error);

    when(ex.getBindingResult()).thenReturn(bindingResult);
    when(bindingResult.getFieldErrors()).thenReturn(fieldErrors);

    ResponseEntity<Object> response =
        exceptionHandler.handleMethodArgumentNotValid(
            ex, headers, HttpStatus.BAD_REQUEST, webRequest);

    assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    assertTrue(response.getBody() instanceof ErrorResponse);
    assertEquals("Error message", ((ErrorResponse) response.getBody()).getError());
  }

  @Test
  void handleMissingServletRequestParameter() {
    MissingServletRequestParameterException ex =
        new MissingServletRequestParameterException("param", "String");

    ResponseEntity<Object> response =
        exceptionHandler.handleMissingServletRequestParameter(
            ex, headers, HttpStatus.BAD_REQUEST, webRequest);

    assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    assertEquals("Missing Request Parameter", ((ErrorResponse) response.getBody()).getError());
  }

  @Test
  void handleInvalidCredentialsException() {
    GlobalExceptionHandler.InvalidCredentialsException ex =
        new GlobalExceptionHandler.InvalidCredentialsException("Invalid credentials");

    ResponseEntity<ErrorResponse> response = exceptionHandler.handleInvalidCredentialsException(ex);

    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    assertEquals("Invalid credentials", response.getBody().getError());
  }

  @Test
  void handleOtpVerificationException() {
    GlobalExceptionHandler.OTPVerificationException ex =
        new GlobalExceptionHandler.OTPVerificationException("Invalid credentials");

    ResponseEntity<ErrorResponse> response = exceptionHandler.handleOtpVerificationException(ex);

    assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    assertEquals("Invalid credentials", response.getBody().getError());
  }

  @Test
  void handleResetPasswordException() {
    GlobalExceptionHandler.ResetPasswordException ex =
        new GlobalExceptionHandler.ResetPasswordException("Invalid credentials");

    ResponseEntity<ErrorResponse> response = exceptionHandler.handleResetPasswordException(ex);

    assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    assertEquals("Invalid credentials", response.getBody().getError());
  }

  @Test
  void handleBadCredentialsException() {
    BadCredentialsException ex = new BadCredentialsException("Bad credentials");

    ResponseEntity<ErrorResponse> response = exceptionHandler.handleBadCredentialsException(ex);

    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    assertEquals("Invalid Credentials", response.getBody().getError());
  }

  @Test
  void handleRefreshTokenException() {
    GlobalExceptionHandler.RefreshTokenException ex =
        new GlobalExceptionHandler.RefreshTokenException("Invalid refresh token");

    ResponseEntity<ErrorResponse> response = exceptionHandler.handleRefreshTokenException(ex);

    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    assertEquals("Invalid refresh token", response.getBody().getError());
  }

  @Test
  void handleNoSuchElementException() {
    NoSuchElementException ex = new NoSuchElementException();

    ResponseEntity<ErrorResponse> response = exceptionHandler.handleNoSuchElementException(ex);

    assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    assertEquals("User is not registered", response.getBody().getError());
  }

  @Test
  void handleIllegalArgumentException() {
    IllegalArgumentException ex = new IllegalArgumentException("Invalid argument");

    ResponseEntity<ErrorResponse> response = exceptionHandler.handleIllegalArgumentException(ex);

    assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    assertEquals("Invalid argument", response.getBody().getError());
  }

  @Test
  void handleSesV2Exception() {
    GlobalExceptionHandler.SesV2Exception ex =
        new GlobalExceptionHandler.SesV2Exception("Email send failed");

    ResponseEntity<ErrorResponse> response = exceptionHandler.handleSesV2Exception(ex);

    assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    assertEquals("Failed to send email", response.getBody().getError());
  }

  @Test
  void handleInvalidPasswordAttempt() {
    GlobalExceptionHandler.InvalidPasswordException ex =
        new GlobalExceptionHandler.InvalidPasswordException("Invalid password", 2);

    ResponseEntity<ErrorResponse> response = exceptionHandler.handleInvalidPasswordAttempt(ex);

    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    assertEquals("Invalid Credentials", response.getBody().getError());
    // assertEquals(2, response.getBody().getAttempts());
  }

  @Test
  void handleInvalidUserStatus() {
    GlobalExceptionHandler.InvalidUserStatus ex =
        new GlobalExceptionHandler.InvalidUserStatus("User is locked");

    ResponseEntity<ErrorResponse> response = exceptionHandler.handleInvalidUserStatusException(ex);

    assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
    assertEquals("User is locked", response.getBody().getError());
  }

  @Test
  void handleOtpExpiredException() {
    GlobalExceptionHandler.OTPExpiredException ex =
        new GlobalExceptionHandler.OTPExpiredException("OTP expired");

    ResponseEntity<ErrorResponse> response = exceptionHandler.handleOtpExpiredException(ex);

    assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    assertEquals("OTP expired", response.getBody().getError());
  }

  @Test
  void handleGenericException() {
    GlobalExceptionHandler.GenericException ex =
        new GlobalExceptionHandler.GenericException("OTP expired");

    ResponseEntity<ErrorResponse> response = exceptionHandler.handleGenericException(ex);

    assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    assertEquals("OTP expired", response.getBody().getError());
  }

  @Test
  void handleSamePasswordException() {
    GlobalExceptionHandler.SamePasswordException ex =
        new GlobalExceptionHandler.SamePasswordException("Same password used");

    ResponseEntity<ErrorResponse> response = exceptionHandler.handleSamePasswordException(ex);

    assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    assertEquals("Same password used", response.getBody().getError());
  }

  @Test
  void handleException() {
    Exception ex = new Exception("Unexpected error");

    ResponseEntity<ErrorResponse> response = exceptionHandler.handleGenericException(ex);

    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    assertEquals("Internal Server Error", response.getBody().getError());
  }
}
