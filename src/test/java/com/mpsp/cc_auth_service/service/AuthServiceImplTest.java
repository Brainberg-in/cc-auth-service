package com.mpsp.cc_auth_service.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.mpsp.cc_auth_service.dto.LoginRequest;
import com.mpsp.cc_auth_service.dto.LoginResponse;
import com.mpsp.cc_auth_service.dto.ResetPasswordRequest;
import com.mpsp.cc_auth_service.dto.User;


import com.mpsp.cc_auth_service.entity.PasswordHistory;
import com.mpsp.cc_auth_service.entity.RefreshToken;
import com.mpsp.cc_auth_service.feignclients.UserServiceClient;
import com.mpsp.cc_auth_service.repository.LoginHistoryRepo;
import com.mpsp.cc_auth_service.repository.PasswordHistoryRepo;
import com.mpsp.cc_auth_service.repository.RefreshTokenRepo;
import com.mpsp.cc_auth_service.service.impl.AuthServiceImpl;
import com.mpsp.cc_auth_service.utils.GlobalExceptionHandler;
import com.mpsp.cc_auth_service.utils.JwtTokenProvider;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {AuthServiceImpl.class})
class AuthServiceImplTest {

  @Autowired private transient AuthServiceImpl authService;

  @MockBean private transient UserServiceClient userService;

  @MockBean private transient PasswordEncoder passwordEncoder;

  @MockBean private transient JwtTokenProvider jwtTokenProvider;

  @MockBean private transient LoginHistoryRepo loginHistoryRepository;

  @MockBean private transient PasswordHistoryRepo passwordHistoryRepository;

  @MockBean private transient RefreshTokenRepo refreshTokenRepository;

  @MockBean private transient OtpService otpService;

  @MockBean private transient AwsService awsService;

  private User user;
  private PasswordHistory passwordHistory;
  private RefreshToken refreshToken;

  @BeforeEach
  void setUp() {
    user = new User();
    user.setUserId(1);
    user.setEmail("test@example.com");
   /// user.setMfaEnabled(false);

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
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class))).thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
    when(jwtTokenProvider.generateToken(user, false)).thenReturn("jwtToken");
    when(jwtTokenProvider.generateToken(user, true)).thenReturn("refreshToken");

    final LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");

    final LoginResponse response = authService.login(loginRequest);

    assertNotNull(response);
    assertEquals("jwtToken", response.getToken());
    assertEquals("refreshToken", response.getRefreshToken());
  }


  @Test
  void testLoginInvalidPassword() {
    when(userService.findByEmail(anyString())).thenReturn(user);
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class))).thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

    LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");

    assertThrows(BadCredentialsException.class, () -> authService.login(loginRequest));
  }

//  @Test
//  void testLogout() throws ParseException {
//    LoginHistory loginHistory = new LoginHistory();
//    loginHistory.setUserId(1);
//
//    when(loginHistoryRepository.findByUserId(anyInt())).thenReturn(loginHistory);
//
//    authService.logout("toekn");
//
//    verify(refreshTokenRepository, times(1)).deleteRefreshToken(anyInt());
//    verify(loginHistoryRepository, times(1)).saveAndFlush(any(LoginHistory.class));
//  }

  @Test
  void testRefreshTokenSuccess() throws ParseException {
    when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(refreshToken));
    when(userService.findById(anyInt())).thenReturn(user);
    when(jwtTokenProvider.generateToken(user, false)).thenReturn("newJwtToken");
    when(jwtTokenProvider.generateToken(user, true)).thenReturn("newRefreshToken");

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
    when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(refreshToken));

    assertThrows(RuntimeException.class, () -> authService.refreshToken("expiredToken"));
  }
  

  @Test
  public void testSendResetPasswordEmail_Success() {
    User user = new User();
    user.setUserId(1);
    when(userService.findByEmail(anyString())).thenReturn(user);
    doNothing().when(awsService).sendEmail(anyString(), anyString(), anyString(), anyMap());

    authService.sendResetPasswordEmail("test@example.com");

    verify(awsService, times(1)).sendEmail(anyString(), anyString(), anyString(), anyMap());
  }

  @Test
  public void testResetPassword_InvalidToken() throws ParseException {
    ResetPasswordRequest resetPasswordRequest = new ResetPasswordRequest();
    resetPasswordRequest.setPassword("newPassword");

    when(jwtTokenProvider.getSubject(anyString())).thenThrow(ParseException.class);

    assertThrows(GlobalExceptionHandler.RefreshTokenException.class, () -> authService.resetPassword(resetPasswordRequest, "invalidToken"));
  }

  @Test
  public void testResetPassword_Success() throws ParseException {
    ResetPasswordRequest resetPasswordRequest = new ResetPasswordRequest();
    resetPasswordRequest.setPassword("newPassword");

    PasswordHistory passwordHistory = new PasswordHistory();
    passwordHistory.setUserId(1);
    passwordHistory.setCurrentPassword("encodedPassword");

    when(jwtTokenProvider.getSubject(anyString())).thenReturn("1");
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class))).thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.encode(anyString())).thenReturn("encodedNewPassword");

    authService.resetPassword(resetPasswordRequest, "validToken");

    verify(passwordHistoryRepository, times(1)).save(any(PasswordHistory.class));
  }
}
