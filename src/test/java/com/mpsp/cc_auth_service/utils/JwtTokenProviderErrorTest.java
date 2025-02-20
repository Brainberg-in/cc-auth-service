package com.mpsp.cc_auth_service.utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.mpsp.cc_auth_service.dto.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
public class JwtTokenProviderErrorTest {

  @InjectMocks private JwtTokenProvider jwtTokenProvider;

  @Mock private User user;

  @BeforeEach
  public void setUp() {
    MockitoAnnotations.openMocks(this);
    ReflectionTestUtils.setField(jwtTokenProvider, "jwtSecret", "abcd");
    ReflectionTestUtils.setField(jwtTokenProvider, "jwtExpiration", 3600000L);
    ReflectionTestUtils.setField(jwtTokenProvider, "refreshTokenExpiration", 7200000L);
  }

  @Test
  public void testGenerateToken() {
    when(user.getUserId()).thenReturn(1);

    assertThrows(
        RuntimeException.class,
        () -> jwtTokenProvider.generateToken(user, false, "PRINCIPAL", true));
  }

  @Test
  public void testVerifyToken() {
    assertFalse(jwtTokenProvider.verifyToken("token", "1", false));
  }
}
