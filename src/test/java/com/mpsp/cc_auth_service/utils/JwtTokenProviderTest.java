package com.mpsp.cc_auth_service.utils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.mpsp.cc_auth_service.constants.AppConstants;
import com.mpsp.cc_auth_service.dto.User;
import java.text.ParseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
public class JwtTokenProviderTest {

  @InjectMocks private JwtTokenProvider jwtTokenProvider;

  @Mock private User user;

  @BeforeEach
  public void setUp() {
    MockitoAnnotations.openMocks(this);
    ReflectionTestUtils.setField(
        jwtTokenProvider, "jwtSecret", "c29tZXNlY3JldGtleTEyM2Zvcmp3dGJhc2VzY3JldDEyMzQ1Njc4OTA=");
    ReflectionTestUtils.setField(jwtTokenProvider, "jwtExpiration", 3600000L);
    ReflectionTestUtils.setField(jwtTokenProvider, "refreshTokenExpiration", 7200000L);
  }

  @Test
  public void testGenerateToken() {
    when(user.getUserId()).thenReturn(1);
    final String token = jwtTokenProvider.generateToken(user, false, "", false);
    // System.out.println(token);
    assertNotNull(token);
  }

  @Test
  public void testGenerateRefreshToken() {
    when(user.getUserId()).thenReturn(1);
    final String token = jwtTokenProvider.generateToken(user, true, "", false);
    // System.out.println(token);
    assertNotNull(token);
  }

  @Test
  public void testExpiredToken() {
    final String token =
        "eyJhbGciOiJIUzI1NiJ9.eyJpc1JlZnJlc2hUb2tlbiI6ZmFsc2UsImlzcyI6InRyYWl0Zml0Iiwic3ViIjoiMSIsImV4cCI6MTcyNTMxMDg3NiwiaWF0IjoxNzI1MzMzNzc2fQ.KxHSEIyOWl015P3jN3ArdnK8r5LyohnrtdgH-iuRu7U";
    assertFalse(jwtTokenProvider.verifyToken(token, "1", false, false));
  }

  @Test
  public void testInvalidSignature() {
    final String token =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3MjUzMzM5OTIsImV4cCI6MTc1Njg2OTk5MiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.s5n63psR24KQdTm43RK0ttjOpg6tCGBWAgVnaOEzvM4";
    assertFalse(jwtTokenProvider.verifyToken(token, "1", false, false));
  }

  @Test
  public void testParseException() {
    final String token = "eyJ0eXAiOi";
    assertFalse(jwtTokenProvider.verifyToken(token, "1", false, false));
  }

  @Test
  void testVerifyToken() {
    when(user.getUserId()).thenReturn(1);
    final String token = jwtTokenProvider.generateToken(user, false, "", true);
    assertDoesNotThrow(() -> jwtTokenProvider.verifyToken(token, "1", false, false));
  }

  @Test
  void testVerifyBearerToken() {
    when(user.getUserId()).thenReturn(1);
    final String token = jwtTokenProvider.generateToken(user, false, "", true);
    assertDoesNotThrow(
        () ->
            jwtTokenProvider.verifyToken(
                String.join("", AppConstants.BEARER, token), "1", false, true));
  }

  @Test
  public void testGetClaim() {
    final String token = jwtTokenProvider.generateToken(user, false, "", true);
    assertEquals("false", jwtTokenProvider.getClaim(token, AppConstants.IS_REFRESHTOKEN));
  }

  @Test
  public void testGetEmail() {
    when(user.getEmail()).thenReturn("test@example.com");
    final String token = jwtTokenProvider.generateToken(user, false, "", false);
    assertEquals("test@example.com", jwtTokenProvider.getUserEmail(token));
  }

  @Test
  public void testGetEmailException() {
    assertThrows(
        GlobalExceptionHandler.RefreshTokenException.class,
        () -> jwtTokenProvider.getUserEmail("Bearer invalidToken"));
  }

  @Test
  public void testGetClaimBearer() {
    final String token = jwtTokenProvider.generateToken(user, false, "", false);
    assertEquals(
        "false",
        jwtTokenProvider.getClaim(
            String.join("", AppConstants.BEARER, token), AppConstants.IS_REFRESHTOKEN));
  }

  @Test
  public void testGetSubject() throws ParseException {
    when(user.getUserId()).thenReturn(1);
    String token = jwtTokenProvider.generateToken(user, false, "", false);
    String subject = jwtTokenProvider.getSubject(token);
    assertEquals("1", subject);
  }

  @Test
  public void testGetSubjectBearer() throws ParseException {
    when(user.getUserId()).thenReturn(1);
    String token = jwtTokenProvider.generateToken(user, false, "", false);
    String subject = jwtTokenProvider.getSubject(String.join("", AppConstants.BEARER, token));
    assertEquals("1", subject);
  }

  @Test
  public void testGetSubjectBearerException() throws ParseException {
    assertThrows(
        GlobalExceptionHandler.RefreshTokenException.class,
        () -> jwtTokenProvider.getSubject(String.join("", AppConstants.BEARER, "invalidToken")));
  }
}
