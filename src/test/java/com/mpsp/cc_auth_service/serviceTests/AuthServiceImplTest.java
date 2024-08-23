package com.mpsp.cc_auth_service.serviceTests;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.mpsp.cc_auth_service.dto.LoginRequest;
import com.mpsp.cc_auth_service.dto.LoginResponse;
import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.entity.LoginHistory;
import com.mpsp.cc_auth_service.entity.PasswordHistory;
import com.mpsp.cc_auth_service.entity.RefreshToken;
import com.mpsp.cc_auth_service.repository.LoginHistoryRepo;
import com.mpsp.cc_auth_service.repository.PasswordHistoryRepo;
import com.mpsp.cc_auth_service.repository.RefreshTokenRepo;
import com.mpsp.cc_auth_service.service.OtpService;
import com.mpsp.cc_auth_service.service.UserService;
import com.mpsp.cc_auth_service.service.impl.AuthServiceImpl;
import com.mpsp.cc_auth_service.utils.JwtTokenProvider;
import java.time.LocalDateTime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

  @Mock private UserService userService;

  @Mock private PasswordEncoder passwordEncoder;

  @Mock private JwtTokenProvider jwtTokenProvider;

  @Mock private LoginHistoryRepo loginHistoryRepository;

  @Mock private PasswordHistoryRepo passwordHistoryRepository;

  @Mock private RefreshTokenRepo refreshTokenRepository;

  @Mock private OtpService otpService;

  @InjectMocks private AuthServiceImpl authService;

  private User user;
  private PasswordHistory passwordHistory;
  private RefreshToken refreshToken;

  @BeforeEach
  void setUp() {
    user = new User();
    user.setUserId(1);
    user.setEmail("test@example.com");
    user.setMfaEnabled(false);

    passwordHistory = new PasswordHistory();
    passwordHistory.setUserId(1);
    passwordHistory.setCurrentPassword("encodedPassword");

    refreshToken = new RefreshToken();
    refreshToken.setUserId(1);
    refreshToken.setToken("refreshToken");
    refreshToken.setExpiresAt(LocalDateTime.now().plusDays(1));
  }

  @Test
  void testLoginSuccess() {
    when(userService.findByEmail(anyString())).thenReturn(user);
    when(passwordHistoryRepository.findByUserId(anyInt())).thenReturn(passwordHistory);
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
    when(jwtTokenProvider.generateToken(any(User.class), anyBoolean())).thenReturn("jwtToken");
    when(jwtTokenProvider.generateToken(any(User.class), anyBoolean())).thenReturn("refreshToken");

    LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");

    LoginResponse response = authService.login(loginRequest);

    assertNotNull(response);
    assertEquals("jwtToken", response.getToken());
    assertEquals("refreshToken", response.getRefreshToken());
  }

  @Test
  void testLoginUserNotFound() {
    when(userService.findByEmail(anyString())).thenReturn(null);

    LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");

    assertThrows(UsernameNotFoundException.class, () -> authService.login(loginRequest));
  }

  @Test
  void testLoginInvalidPassword() {
    when(userService.findByEmail(anyString())).thenReturn(user);
    when(passwordHistoryRepository.findByUserId(anyInt())).thenReturn(passwordHistory);
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

    LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");

    assertThrows(BadCredentialsException.class, () -> authService.login(loginRequest));
  }

  @Test
  void testLogout() {
    LoginHistory loginHistory = new LoginHistory();
    loginHistory.setUserId(1);

    when(loginHistoryRepository.findByUserId(anyInt())).thenReturn(loginHistory);

    authService.logout(1);

    verify(refreshTokenRepository, times(1)).deleteRefreshToken(anyInt());
    verify(loginHistoryRepository, times(1)).saveAndFlush(any(LoginHistory.class));
  }

  @Test
  void testRefreshTokenSuccess() {
    when(refreshTokenRepository.findByToken(anyString())).thenReturn(refreshToken);
    when(userService.findById(anyInt())).thenReturn(user);
    when(jwtTokenProvider.generateToken(any(User.class), anyBoolean())).thenReturn("newJwtToken");
    when(jwtTokenProvider.generateToken(any(User.class), anyBoolean()))
        .thenReturn("newRefreshToken");

    LoginResponse response = authService.refreshToken("refreshToken");

    assertNotNull(response);
    assertEquals("newJwtToken", response.getToken());
    assertEquals("newRefreshToken", response.getRefreshToken());
  }

  @Test
  void testRefreshTokenInvalid() {
    when(refreshTokenRepository.findByToken(anyString())).thenReturn(null);

    assertThrows(RuntimeException.class, () -> authService.refreshToken("invalidToken"));
  }

  @Test
  void testRefreshTokenExpired() {
    refreshToken.setExpiresAt(LocalDateTime.now().minusDays(1));
    when(refreshTokenRepository.findByToken(anyString())).thenReturn(refreshToken);

    assertThrows(RuntimeException.class, () -> authService.refreshToken("expiredToken"));
  }
}
