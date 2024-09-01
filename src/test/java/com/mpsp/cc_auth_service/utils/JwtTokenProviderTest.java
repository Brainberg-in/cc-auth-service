package com.mpsp.cc_auth_service.utils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.mpsp.cc_auth_service.dto.User;
import com.nimbusds.jose.JOSEException;
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
    String token = jwtTokenProvider.generateToken(user, false);
    assertNotNull(token);
  }

  @Test
  public void testVerifyToken() throws ParseException, JOSEException {
    when(user.getUserId()).thenReturn(1);
    String token = jwtTokenProvider.generateToken(user, false);
    assertDoesNotThrow(() -> jwtTokenProvider.verifyToken(token, "1", false));
  }

  @Test
  public void testGetSubject() throws ParseException {
    when(user.getUserId()).thenReturn(1);
    String token = jwtTokenProvider.generateToken(user, false);
    String subject = jwtTokenProvider.getSubject(token);
    assertEquals("1", subject);
  }
}
