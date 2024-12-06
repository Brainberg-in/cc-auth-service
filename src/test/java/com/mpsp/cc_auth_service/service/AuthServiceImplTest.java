package com.mpsp.cc_auth_service.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.mpsp.cc_auth_service.constants.UserStatus;
import com.mpsp.cc_auth_service.dto.ChangePasswordRequest;
import com.mpsp.cc_auth_service.dto.LoginRequest;
import com.mpsp.cc_auth_service.dto.LoginResponse;
import com.mpsp.cc_auth_service.dto.ResetPasswordRequest;
import com.mpsp.cc_auth_service.dto.SchoolDetails;
import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.dto.UserDetails;
import com.mpsp.cc_auth_service.entity.PasswordHistory;
import com.mpsp.cc_auth_service.entity.RefreshToken;
import com.mpsp.cc_auth_service.entity.ResetPassword;
import com.mpsp.cc_auth_service.feignclients.SchoolServiceClient;
import com.mpsp.cc_auth_service.feignclients.UserServiceClient;
import com.mpsp.cc_auth_service.repository.LoginHistoryRepo;
import com.mpsp.cc_auth_service.repository.PasswordHistoryRepo;
import com.mpsp.cc_auth_service.repository.RefreshTokenRepo;
import com.mpsp.cc_auth_service.repository.ResetPasswordRepo;
import com.mpsp.cc_auth_service.service.impl.AuthServiceImpl;
import com.mpsp.cc_auth_service.utils.GlobalExceptionHandler;
import com.mpsp.cc_auth_service.utils.GlobalExceptionHandler.GenericException;
import com.mpsp.cc_auth_service.utils.JwtTokenProvider;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {AuthServiceImpl.class})
@TestPropertySource(
    locations = {"classpath:application.properties", "classpath:application-dev.properties"})
class AuthServiceImplTest {

  @Autowired private transient AuthServiceImpl authService;

  @MockBean private transient UserServiceClient userService;

  @MockBean private transient PasswordEncoder passwordEncoder;

  @MockBean private transient JwtTokenProvider jwtTokenProvider;

  @MockBean private transient LoginHistoryRepo loginHistoryRepository;

  @MockBean private transient PasswordHistoryRepo passwordHistoryRepository;

  @MockBean private transient RefreshTokenRepo refreshTokenRepository;

  @MockBean private transient OtpService otpService;

  @MockBean private transient NotificationService notificationService;

  @MockBean private transient ResetPasswordRepo resetPasswordRepo;

  @MockBean private transient SchoolServiceClient schoolService;

  @MockBean private transient JdbcTemplate jdbcTemplate;

  @Mock private UserDetails userDetails;
  @Mock private SchoolDetails schoolDetails;
  private User user;
  private PasswordHistory passwordHistory;
  private RefreshToken refreshToken;

  @BeforeEach
  void setUp() {
    user = new User();
    user.setUserId(1);
    user.setEmail("test@example.com");
    user.setStatus(UserStatus.ACTIVE);
    /// user.setMfaEnabled(false);

    passwordHistory = new PasswordHistory();
    passwordHistory.setUserId(1);
    passwordHistory.setCurrentPassword("encodedPassword");
    passwordHistory.setUserRole("");
    refreshToken = new RefreshToken();
    refreshToken.setUserId(1);
    refreshToken.setToken("refreshToken");
    refreshToken.setExpiresAt(LocalDateTime.now().plusDays(1));
  }

  @Test
  void testLoginSuccess() {
    when(userService.findByEmail(anyString())).thenReturn(user);
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);

    when(jwtTokenProvider.generateToken(user, false, "")).thenReturn("jwtToken");
    when(jwtTokenProvider.generateToken(user, true, "")).thenReturn("refreshToken");

    final LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");

    final LoginResponse response = authService.login(loginRequest, "127.0.0.1");

    assertNotNull(response);
    assertEquals("jwtToken", response.getAccessToken());
    assertEquals("refreshToken", response.getRefreshToken());
  }

  @Test
  void testLoginInvalidPassword() {
    when(userService.findByEmail(anyString())).thenReturn(user);
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

    LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");

    assertThrows(
        GlobalExceptionHandler.InvalidPasswordException.class,
        () -> authService.login(loginRequest, "127.0.0.1"));
  }

  // @Test
  // void testLogout() throws ParseException {
  // LoginHistory loginHistory = new LoginHistory();
  // loginHistory.setUserId(1);
  //
  // when(loginHistoryRepository.findByUserId(anyInt())).thenReturn(loginHistory);
  //
  // authService.logout("toekn");
  //
  // verify(refreshTokenRepository, times(1)).deleteRefreshToken(anyInt());
  // verify(loginHistoryRepository,
  // times(1)).saveAndFlush(any(LoginHistory.class));
  // }

  @Test
  void testRefreshTokenSuccess() throws ParseException {
    when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(refreshToken));
    when(userService.findById(anyInt())).thenReturn(user);
    when(jwtTokenProvider.generateToken(user, false, "")).thenReturn("newJwtToken");
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    LoginResponse response = authService.refreshToken("refreshToken");

    assertNotNull(response);
    assertEquals("newJwtToken", response.getAccessToken());
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
    doNothing()
        .when(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());

    authService.sendResetPasswordEmail("test@example.com");

    verify(notificationService, times(1))
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
  }

  @Test
  void changePassword_Success() throws ParseException {
    // Create a request with the current and new password
    ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
    changePasswordRequest.setPassword("newPassword");
    changePasswordRequest.setCurrentPassword("currentPassword");
    PasswordHistory passwordHistory = new PasswordHistory();
    passwordHistory.setUserId(1);
    passwordHistory.setCurrentPassword("encodedCurrentPassword");
    when(jwtTokenProvider.getSubject(anyString())).thenReturn("1");
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(
            changePasswordRequest.getCurrentPassword(), passwordHistory.getCurrentPassword()))
        .thenReturn(true);
    when(passwordEncoder.matches(
            changePasswordRequest.getPassword(), passwordHistory.getCurrentPassword()))
        .thenReturn(false);
    when(userService.findById(anyInt())).thenReturn(user);
    authService.changePassword(changePasswordRequest, "validToken");
    verify(passwordHistoryRepository, times(1)).save(any(PasswordHistory.class));
  }

  @Test
  void changePassword_InvalidCurrentPassword() throws ParseException {
    ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
    changePasswordRequest.setPassword("newPassword");
    changePasswordRequest.setCurrentPassword("wrongPassword");

    PasswordHistory passwordHistory = new PasswordHistory();
    passwordHistory.setUserId(1);
    passwordHistory.setCurrentPassword("encodedPassword");

    when(jwtTokenProvider.getSubject(anyString())).thenReturn("1");
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

    assertThrows(
        GlobalExceptionHandler.InvalidCredentialsException.class,
        () -> authService.changePassword(changePasswordRequest, "validToken"));
  }

  @Test
  void changePassword_SameAsCurrentPassword() throws ParseException {
    ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
    changePasswordRequest.setPassword("encodedPassword");
    changePasswordRequest.setCurrentPassword("encodedPassword");

    PasswordHistory passwordHistory = new PasswordHistory();
    passwordHistory.setUserId(1);
    passwordHistory.setCurrentPassword("encodedPassword");

    when(jwtTokenProvider.getSubject(anyString())).thenReturn("1");
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);

    assertThrows(
        GlobalExceptionHandler.SamePasswordException.class,
        () -> authService.changePassword(changePasswordRequest, "validToken"));
  }

  @Test
  void changePassword_NoCurrentPasswordProvided() throws ParseException {
    ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
    changePasswordRequest.setPassword("newPassword");

    PasswordHistory passwordHistory = new PasswordHistory();
    passwordHistory.setUserId(1);
    passwordHistory.setCurrentPassword("encodedPassword");

    when(jwtTokenProvider.getSubject(anyString())).thenReturn("1");
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.encode(anyString())).thenReturn("encodedNewPassword");
    when(userService.findById(anyInt())).thenReturn(user);

    authService.changePassword(changePasswordRequest, "validToken");

    verify(passwordHistoryRepository, times(1)).save(any(PasswordHistory.class));
  }

  @Test
  void sendResetPasswordEmail_Success() {
    User user = new User();
    user.setUserId(1);
    user.setEmail("test@example.com");

    when(userService.findByEmail(anyString())).thenReturn(user);
    doNothing()
        .when(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());

    authService.sendResetPasswordEmail("test@example.com");

    verify(notificationService, times(1))
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
  }

  @Test
  void resetPassword_Success() {
    ResetPasswordRequest resetPasswordRequest = new ResetPasswordRequest();
    resetPasswordRequest.setPassword("newPassword");
    resetPasswordRequest.setResetToken("validToken");

    ResetPassword resetPassword = new ResetPassword();
    resetPassword.setUserId(1);
    resetPassword.setResetToken("validToken");
    resetPassword.setLinkExpired(false);

    PasswordHistory passwordHistory = new PasswordHistory();
    passwordHistory.setUserId(1);
    passwordHistory.setCurrentPassword("encodedPassword");

    when(resetPasswordRepo.findByResetToken(anyString())).thenReturn(Optional.of(resetPassword));
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.encode(anyString())).thenReturn("encodedNewPassword");

    authService.resetPasswordSelf(resetPasswordRequest);

    verify(passwordHistoryRepository, times(1)).saveAndFlush(any(PasswordHistory.class));
    verify(resetPasswordRepo, times(1)).saveAndFlush(any(ResetPassword.class));
  }

  @Test
  void resetPassword_InvalidToken() {
    ResetPasswordRequest resetPasswordRequest = new ResetPasswordRequest();
    resetPasswordRequest.setPassword("newPassword");
    resetPasswordRequest.setResetToken("invalidToken");

    when(resetPasswordRepo.findByResetToken(anyString())).thenReturn(Optional.empty());

    assertThrows(GenericException.class, () -> authService.resetPasswordSelf(resetPasswordRequest));
  }

  @Test
  void resetPassword_ExpiredToken() {
    ResetPasswordRequest resetPasswordRequest = new ResetPasswordRequest();
    resetPasswordRequest.setPassword("newPassword");
    resetPasswordRequest.setResetToken("expiredToken");

    ResetPassword resetPassword = new ResetPassword();
    resetPassword.setUserId(1);
    resetPassword.setResetToken("expiredToken");
    resetPassword.setLinkExpired(true);

    when(resetPasswordRepo.findByResetToken(anyString())).thenReturn(Optional.of(resetPassword));

    assertThrows(
        GlobalExceptionHandler.GenericException.class,
        () -> authService.resetPasswordSelf(resetPasswordRequest));
  }

  // @Test
  // void test_resetPasswordByAdmin_whenScoolDoesNotMatch() {
  //   when(jwtTokenProvider.getSubject(Mockito.anyString())).thenReturn("1");
  //   when(jwtTokenProvider.getClaim("token", AppConstants.USER_ROLE))
  //       .thenReturn(UserRole.PRINCIPAL.name());
  //   when(userService.getUserDetails(1, "students")).thenReturn(userDetails);
  //   when(userDetails.getSchoolId()).thenReturn(2);
  //   when(userDetails.getUser()).thenReturn(user);
  //   when(schoolService.getSchoolDetails(2, true)).thenReturn(schoolDetails);
  //   when(schoolDetails.getPrincipalUserId()).thenReturn(2);

  //   final ResetPasswordRequest resetPasswordRequest = new ResetPasswordRequest();

  //   resetPasswordRequest.setBehalfOf(List.of(new UserIdAndRole(1, "STUDENT")));

  //   assertThrows(
  //       GlobalExceptionHandler.ResetPasswordException.class,
  //       () -> authService.resetPasswordByAdmin(resetPasswordRequest, "token"));
  // }

  // @Test
  // void test_resetPasswordByAdmin_whenScoolDoesMatch_andPasswordMatches() {
  //   when(jwtTokenProvider.getSubject(Mockito.anyString())).thenReturn("1");
  //   when(jwtTokenProvider.getClaim("token", AppConstants.USER_ROLE))
  //       .thenReturn(UserRole.PRINCIPAL.name());
  //   when(userService.getUserDetails(1, "students")).thenReturn(userDetails);
  //   when(userDetails.getSchoolId()).thenReturn(2);
  //   when(schoolService.getSchoolDetails(2, true)).thenReturn(schoolDetails);
  //   when(schoolDetails.getPrincipalUserId()).thenReturn(1);
  //   when(passwordHistoryRepository.findAllByUserId(
  //           1, PageRequest.of(0, 1, Sort.by("logoutTime").descending())))
  //       .thenReturn(new PageImpl<>(List.of(passwordHistory)));
  //   when(userDetails.getUser()).thenReturn(user);
  //   when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
  //   final ResetPasswordRequest resetPasswordRequest = new ResetPasswordRequest();
  //   resetPasswordRequest.setPassword("newPassword");
  //   resetPasswordRequest.setBehalfOf(List.of(new UserIdAndRole(1, "STUDENT")));

  //   assertThrows(
  //       GlobalExceptionHandler.SamePasswordException.class,
  //       () -> authService.resetPasswordByAdmin(resetPasswordRequest, "token"));
  // }

  // @Test
  // void test_resetPasswordByAdmin_whenScoolDoesMatch() {
  //   when(userDetails.getUser()).thenReturn(user);
  //   when(jwtTokenProvider.getSubject(Mockito.anyString())).thenReturn("1");
  //   when(jwtTokenProvider.getClaim("token", AppConstants.USER_ROLE))
  //       .thenReturn(UserRole.PRINCIPAL.name());
  //   when(userService.getUserDetails(1, "students")).thenReturn(userDetails);
  //   when(userDetails.getSchoolId()).thenReturn(2);
  //   when(schoolService.getSchoolDetails(2, true)).thenReturn(schoolDetails);
  //   when(schoolDetails.getPrincipalUserId()).thenReturn(1);
  //   when(passwordHistoryRepository.findAllByUserId(
  //           1, PageRequest.of(0, 1, Sort.by("logoutTime").descending())))
  //       .thenReturn(new PageImpl<>(List.of(passwordHistory)));
  //   when(passwordHistoryRepository.saveAndFlush(any(PasswordHistory.class)))
  //       .thenReturn(passwordHistory);
  //   when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);
  //   final ResetPasswordRequest resetPasswordRequest = new ResetPasswordRequest();
  //   resetPasswordRequest.setPassword("newPassword");
  //   resetPasswordRequest.setBehalfOf(List.of(new UserIdAndRole(1, "STUDENT")));
  //   authService.resetPasswordByAdmin(resetPasswordRequest, "token");
  //   Mockito.verify(passwordHistoryRepository, times(1)).saveAndFlush(any(PasswordHistory.class));
  // }
}
