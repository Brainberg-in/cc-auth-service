package com.mpsp.cc_auth_service.utils;

import com.mpsp.cc_auth_service.error.ErrorResponse;
import java.util.List;
import java.util.NoSuchElementException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

  @Override
  @Nullable
  protected ResponseEntity<Object> handleMethodArgumentNotValid(
      final MethodArgumentNotValidException ex,
      final HttpHeaders headers,
      final HttpStatusCode status,
      final WebRequest request) {
    log.error("MethodArgumentNotValidException occurred", ex);
    final List<String> message =
        ex.getBindingResult().getFieldErrors().stream()
            .map(DefaultMessageSourceResolvable::getDefaultMessage)
            .toList();
    return ResponseEntity.badRequest().body(new ErrorResponse(message.get(0)));
  }

  @Override
  protected ResponseEntity<Object> handleMissingServletRequestParameter(
      final MissingServletRequestParameterException ex,
      final HttpHeaders headers,
      final HttpStatusCode status,
      final WebRequest request) {
    log.error("MissingServletRequestParameterException occurred", ex);
    final ErrorResponse response = new ErrorResponse("Missing Request Parameter");
    return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
  }

  // Handle Invalid Credentials Exception
  @ExceptionHandler(InvalidCredentialsException.class)
  public ResponseEntity<ErrorResponse> handleInvalidCredentialsException(
      InvalidCredentialsException ex) {
    log.error("InvalidCredentialsException occurred", ex);
    final ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
    return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
  }

  @ExceptionHandler(BadCredentialsException.class)
  public ResponseEntity<ErrorResponse> handleBadCredentialsException(BadCredentialsException ex) {
    log.error("InvalidCredentialsException occurred", ex);
    final ErrorResponse errorResponse = new ErrorResponse("Invalid Credentials");
    return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
  }

  // Handle Refresh Token Exception
  @ExceptionHandler(RefreshTokenException.class)
  public ResponseEntity<ErrorResponse> handleRefreshTokenException(RefreshTokenException ex) {
    final ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
    return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
  }

  // Handle General Exception
  @ExceptionHandler(Exception.class)
  public ResponseEntity<ErrorResponse> handleGenericException(Exception ex) {
    log.error("Unexpected error occurred", ex);
    final ErrorResponse errorResponse =
        new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
    return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
  }

  @ExceptionHandler(SesV2Exception.class)
  public ResponseEntity<ErrorResponse> handleSesV2Exception(SesV2Exception e) {
    final ErrorResponse errorResponse = new ErrorResponse("Failed to send email");
    return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(NoSuchElementException.class)
  public ResponseEntity<ErrorResponse> handleNoSuchElementException(NoSuchElementException e) {
    log.error("NoSuchElementException occurred", e);
    final ErrorResponse errorResponse = new ErrorResponse("User is not registered");
    return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);
  }

  @ExceptionHandler(IllegalArgumentException.class)
  public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException e) {
    log.error("IllegalArgumentException occurred", e);
    final ErrorResponse errorResponse = new ErrorResponse(e.getMessage());
    return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
  }

  // Custom exception for invalid credentials
  public static class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException(String message) {
      super(message);
    }
  }

  // Custom exception for invalid refresh token
  public static class RefreshTokenException extends RuntimeException {
    public RefreshTokenException(String message) {
      super(message);
    }
  }

  public static class OTPExpiredException extends RuntimeException {
    public OTPExpiredException(String message) {
      super(message);
    }
  }

  public static class OTPVerificationException extends RuntimeException {
    public OTPVerificationException(String message) {
      super(message);
    }
  }

  public static class SamePasswordException extends RuntimeException {
    public SamePasswordException(String message) {
      super(message);
    }
  }

  public static class GenericException extends RuntimeException {
    public GenericException(String message) {
      super(message);
    }
  }

  public static class ResetPasswordException extends RuntimeException {
    public ResetPasswordException(String message) {
      super(message);
    }
  }

  public static class SesV2Exception extends RuntimeException {
    public SesV2Exception(String message) {
      super(message);
    }
  }

  // Custom exception for invalid password
  public static class InvalidPasswordException extends RuntimeException {
    private Integer attempts;

    public InvalidPasswordException(String message, Integer attempts) {
      super(message);
      this.attempts = attempts;
    }

    public Integer getAttempts() {
      return attempts;
    }
  }

  // Custom exception for invalid password
  public static class InvalidUserStatus extends RuntimeException {
    public InvalidUserStatus(String message) {
      super(message);
    }
  }

  @ExceptionHandler(OTPExpiredException.class)
  public ResponseEntity<ErrorResponse> handleOtpExpiredException(OTPExpiredException e) {
    final ErrorResponse errorResponse = new ErrorResponse(e.getMessage());
    return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(SamePasswordException.class)
  public ResponseEntity<ErrorResponse> handleSamePasswordException(SamePasswordException e) {
    final ErrorResponse errorResponse = new ErrorResponse(e.getMessage());
    return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(OTPVerificationException.class)
  public ResponseEntity<ErrorResponse> handleOtpVerificationException(OTPVerificationException e) {
    final ErrorResponse errorResponse = new ErrorResponse(e.getMessage());
    return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(GenericException.class)
  public ResponseEntity<ErrorResponse> handleGenericException(GenericException e) {
    final ErrorResponse errorResponse = new ErrorResponse(e.getMessage());
    return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(ResetPasswordException.class)
  public ResponseEntity<ErrorResponse> handleResetPasswordException(ResetPasswordException e) {
    final ErrorResponse errorResponse = new ErrorResponse(e.getMessage());
    return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
  }

  // Handle Invalid Password Exception
  @ExceptionHandler(InvalidPasswordException.class)
  public ResponseEntity<ErrorResponse> handleInvalidPasswordAttempt(InvalidPasswordException ex) {
    final ErrorResponse errorResponse =
        new ErrorResponse("Invalid Credentials", ex.getMessage(), ex.attempts);
    return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
  }

  // Handle invalid user status exception
  @ExceptionHandler(InvalidUserStatus.class)
  public ResponseEntity<ErrorResponse> handleInvalidUserStatusException(InvalidUserStatus e) {
    final ErrorResponse errorResponse = new ErrorResponse(e.getMessage());
    return new ResponseEntity<>(errorResponse, HttpStatus.FORBIDDEN);
  }
}
