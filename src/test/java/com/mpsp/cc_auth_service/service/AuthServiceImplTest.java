package com.mpsp.cc_auth_service.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.mpsp.cc_auth_service.constants.AppConstants;
import com.mpsp.cc_auth_service.constants.UserRole;
import com.mpsp.cc_auth_service.constants.UserStatus;
import com.mpsp.cc_auth_service.dto.ChangePasswordRequest;
import com.mpsp.cc_auth_service.dto.LoginHistoryResponse;
import com.mpsp.cc_auth_service.dto.LoginRequest;
import com.mpsp.cc_auth_service.dto.LoginResponse;
import com.mpsp.cc_auth_service.dto.ResetPasswordRequest;
import com.mpsp.cc_auth_service.dto.SchoolDetails;
import com.mpsp.cc_auth_service.dto.Student;
import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.dto.UserCreateRequest;
import com.mpsp.cc_auth_service.dto.UserDetails;
import com.mpsp.cc_auth_service.dto.UserIdAndRole;
import com.mpsp.cc_auth_service.entity.LoginHistory;
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
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {AuthServiceImpl.class})
@TestPropertySource(
    properties = {"spring.profiles.active=dev"},
    locations = {"classpath:application.properties", "classpath:application-dev.properties"})
class AuthServiceImplTest {

  @Autowired private transient AuthServiceImpl authService;

  @MockitoBean private transient UserServiceClient userService;

  @MockitoBean private transient PasswordEncoder passwordEncoder;

  @MockitoBean private transient JwtTokenProvider jwtTokenProvider;

  @MockitoBean private transient LoginHistoryRepo loginHistoryRepository;

  @MockitoBean private transient PasswordHistoryRepo passwordHistoryRepository;

  @MockitoBean private transient RefreshTokenRepo refreshTokenRepository;

  @MockitoBean private transient OtpService otpService;

  @MockitoBean private transient NotificationService notificationService;

  @MockitoBean private transient ResetPasswordRepo resetPasswordRepo;

  @MockitoBean private transient SchoolServiceClient schoolService;

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
    user.setFullName("John Doe");
    /// user.setMfaEnabled(false);

    passwordHistory = new PasswordHistory();
    passwordHistory.setUserId(1);
    passwordHistory.setCurrentPassword("encodedPassword");
    passwordHistory.setFailedLoginAttempts(1);
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

    when(jwtTokenProvider.generateToken(user, false, "", true)).thenReturn("jwtToken");
    when(jwtTokenProvider.generateToken(user, true, "", true)).thenReturn("refreshToken");
    when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());
    when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(refreshToken);
    doNothing().when(passwordHistoryRepository).updateFailedLoginAttempts(1, 0);
    final LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");

    final LoginResponse response = authService.login(loginRequest, "127.0.0.1");

    assertNotNull(response);
    assertEquals("jwtToken", response.getAccessToken());
    assertEquals("refreshToken", response.getRefreshToken());
    verify(refreshTokenRepository, times(1)).save(any(RefreshToken.class));
    verify(passwordHistoryRepository, times(1)).updateFailedLoginAttempts(1, 0);
  }

  @Test
  void testLogin_NoPasswordFound() {
    when(userService.findByEmail(anyString())).thenReturn(user);
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(Collections.emptyList()));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);

    when(jwtTokenProvider.generateToken(user, false, "", true)).thenReturn("jwtToken");
    when(jwtTokenProvider.generateToken(user, true, "", true)).thenReturn("refreshToken");
    when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());
    when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(refreshToken);
    doNothing().when(passwordHistoryRepository).updateFailedLoginAttempts(1, 0);
    final LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");

    assertThrows(NoSuchElementException.class, () -> authService.login(loginRequest, "127.0.0.1"));
  }

  @Test
  void testLoginSuccessHandleMFA() {
    user.setMfaEnabled(true);
    when(userService.findByEmail(anyString())).thenReturn(user);
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);

    when(jwtTokenProvider.generateToken(user, false, "", false)).thenReturn("jwtToken");
    when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());
    when(otpService.sendOtp(anyString())).thenReturn("1234");
    when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(refreshToken);
    doNothing().when(passwordHistoryRepository).updateFailedLoginAttempts(1, 0);
    final LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");

    final LoginResponse response = authService.login(loginRequest, "127.0.0.1");

    assertNotNull(response);
    assertEquals("jwtToken", response.getAccessToken());
    assertNull(response.getRefreshToken());
    verify(refreshTokenRepository, times(0)).save(any(RefreshToken.class));
    verify(passwordHistoryRepository, times(1)).updateFailedLoginAttempts(1, 0);
    verify(otpService, times(1)).sendOtp(anyString());
  }

  @Test
  void testLoginStudentFailure() {
    when(userService.findByEmail(anyString())).thenReturn(user);
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);

    when(jwtTokenProvider.generateToken(user, false, "", true)).thenReturn("jwtToken");
    when(jwtTokenProvider.generateToken(user, true, "", true)).thenReturn("refreshToken");

    final LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");
    loginRequest.setRole("STUDENT");

    assertThrows(
        GlobalExceptionHandler.InvalidCredentialsException.class,
        () -> authService.login(loginRequest, "127.0.0.1"));
  }

  @Test
  void testLoginInvalidPassword() {
    when(userService.findByEmail(anyString())).thenReturn(user);
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);
    doNothing().when(passwordHistoryRepository).updateFailedLoginAttempts(1, 2);
    LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");

    assertThrows(
        GlobalExceptionHandler.InvalidPasswordException.class,
        () -> authService.login(loginRequest, "127.0.0.1"));
    verify(passwordHistoryRepository, times(1)).updateFailedLoginAttempts(1, 2);
  }

  @Test
  void testLoginInvalidPassword_student() {
    when(userService.findByEmail(anyString())).thenReturn(user);
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);
    doNothing().when(passwordHistoryRepository).updateFailedLoginAttempts(1, 2);
    LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");
    loginRequest.setRole(UserRole.STUDENT.name());
    loginRequest.setUniqueStudentId("1234");
    final Student student = new Student();
    user.setRole(UserRole.STUDENT);
    student.setUser(user);
    when(userService.findByUniqueStudent(anyString())).thenReturn(student);
    assertThrows(
        GlobalExceptionHandler.InvalidPasswordException.class,
        () -> authService.login(loginRequest, "127.0.0.1"));
    verify(passwordHistoryRepository, times(1)).updateFailedLoginAttempts(1, 2);
  }

  @Test
  void testLoginInvalidPasswordLimitExceeds() {
    when(userService.findByEmail(anyString())).thenReturn(user);
    passwordHistory.setFailedLoginAttempts(100);
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);
    doNothing().when(passwordHistoryRepository).updateFailedLoginAttempts(1, 1);
    LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");

    assertThrows(
        GlobalExceptionHandler.InvalidPasswordException.class,
        () -> authService.login(loginRequest, "127.0.0.1"));
    verify(passwordHistoryRepository, times(1)).updateFailedLoginAttempts(1, 1);
  }

  @Test
  void testLoginInvalidPasswordUserLocking() {
    when(userService.findByEmail(anyString())).thenReturn(user);
    passwordHistory.setFailedLoginAttempts(4);
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);
    doNothing().when(passwordHistoryRepository).updateFailedLoginAttempts(1, 6);
    final Map<String, Object> userDataMap = Map.of("status", UserStatus.LOCKED.toString());
    doNothing().when(userService).updateUser(1, 1, userDataMap);
    LoginRequest loginRequest = new LoginRequest();
    loginRequest.setEmail("test@example.com");
    loginRequest.setPassword("password");

    assertThrows(
        GlobalExceptionHandler.InvalidPasswordException.class,
        () -> authService.login(loginRequest, "127.0.0.1"));
    verify(passwordHistoryRepository, times(1)).updateFailedLoginAttempts(1, 5);
    verify(userService, times(1)).updateUser(1, 1, userDataMap);
  }

  @Test
  void testLogout() throws ParseException {
    LoginHistory loginHistory = new LoginHistory();
    loginHistory.setUserId(1);
    when(jwtTokenProvider.getSubject(anyString())).thenReturn("1");
    when(loginHistoryRepository.findAllByUserId(
            1, PageRequest.of(0, 1, Sort.by("lastLoginTime").descending())))
        .thenReturn(new PageImpl<>(List.of(loginHistory)));
    doNothing().when(refreshTokenRepository).deleteRefreshToken(anyInt());
    authService.logout("token");

    verify(refreshTokenRepository, times(1)).deleteRefreshToken(1);
    verify(loginHistoryRepository, times(1)).save(any(LoginHistory.class));
  }

  @Test
  void testLogoutWhenEmpty() throws ParseException {
    LoginHistory loginHistory = new LoginHistory();
    loginHistory.setUserId(1);
    when(jwtTokenProvider.getSubject(anyString())).thenReturn("1");
    when(loginHistoryRepository.findAllByUserId(
            1, PageRequest.of(0, 1, Sort.by("lastLoginTime").descending())))
        .thenReturn(new PageImpl<>(Collections.emptyList()));
    doNothing().when(refreshTokenRepository).deleteRefreshToken(anyInt());
    authService.logout("token");

    verify(refreshTokenRepository, times(1)).deleteRefreshToken(1);
    verify(loginHistoryRepository, times(0)).save(any(LoginHistory.class));
  }

  @Test
  void testRefreshTokenSuccess() throws ParseException {
    when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(refreshToken));
    when(userService.findById(anyInt())).thenReturn(user);
    when(jwtTokenProvider.generateToken(user, false, "", true)).thenReturn("newJwtToken");
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    LoginResponse response = authService.refreshToken("refreshToken");

    assertNotNull(response);
    assertEquals("newJwtToken", response.getAccessToken());
  }

  @Test
  void testRefreshTokenNotFound() {
    when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());

    assertThrows(
        GlobalExceptionHandler.RefreshTokenException.class,
        () -> authService.refreshToken("invalidToken"));
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
  public void testSendResetPasswordEmail_LimitReached() {
    User user = new User();
    user.setUserId(1);
    when(userService.findByEmail(anyString())).thenReturn(user);
    doNothing()
        .when(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());

    final ResetPassword resetPassword = new ResetPassword();
    resetPassword.setUserId(1);
    resetPassword.setResetToken("resetToken");
    resetPassword.setLinkSent(4);
    resetPassword.setLinkExpired(false);
    resetPassword.setModifiedAt(LocalDateTime.now().minus(Duration.ofMinutes(6)));
    when(resetPasswordRepo.findByUserId(anyInt())).thenReturn(Optional.of(resetPassword));

    assertThrows(
        GlobalExceptionHandler.ResetPasswordException.class,
        () -> authService.sendResetPasswordEmail("test@example.com"));
    verify(notificationService, times(0))
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
  }

  @Test
  public void testSendResetPasswordEmail_LimitNotReached() {
    User user = new User();
    user.setUserId(1);
    when(userService.findByEmail(anyString())).thenReturn(user);
    doNothing()
        .when(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());

    final ResetPassword resetPassword = new ResetPassword();
    resetPassword.setUserId(1);
    resetPassword.setResetToken("resetToken");
    resetPassword.setLinkSent(1);
    resetPassword.setLinkExpired(false);
    resetPassword.setModifiedAt(LocalDateTime.now().minus(Duration.ofMinutes(6)));
    when(resetPasswordRepo.findByUserId(anyInt())).thenReturn(Optional.of(resetPassword));

    authService.sendResetPasswordEmail("test@example.com");
    verify(notificationService, times(1))
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
  }

  @Test
  public void testSendResetPasswordEmail_TimeNotReached() {
    User user = new User();
    user.setUserId(1);
    when(userService.findByEmail(anyString())).thenReturn(user);
    doNothing()
        .when(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());

    final ResetPassword resetPassword = new ResetPassword();
    resetPassword.setUserId(1);
    resetPassword.setResetToken("resetToken");
    resetPassword.setLinkSent(4);
    resetPassword.setLinkExpired(false);
    resetPassword.setModifiedAt(LocalDateTime.now().minus(Duration.ofMinutes(61)));
    when(resetPasswordRepo.findByUserId(anyInt())).thenReturn(Optional.of(resetPassword));

    authService.sendResetPasswordEmail("test@example.com");
    verify(notificationService, times(1))
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
  }

  @Test
  void testChangePassword_StatusNotPresent() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    when(jwtTokenProvider.getClaim(token, AppConstants.USER_STATUS)).thenReturn("");
    assertThrows(
        GlobalExceptionHandler.InvalidCredentialsException.class,
        () -> authService.changePassword(new ChangePasswordRequest(), token));
  }

  @Test
  void testChangePassword_StatusIsLocked() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    when(jwtTokenProvider.getClaim(token, AppConstants.USER_STATUS)).thenReturn("LOCKED");
    assertThrows(
        GlobalExceptionHandler.InvalidCredentialsException.class,
        () -> authService.changePassword(new ChangePasswordRequest(), token));
  }

  @Test
  void changePassword_Success() throws ParseException {
    // Create a request with the current and new password
    final ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
    changePasswordRequest.setPassword("newPassword");
    changePasswordRequest.setCurrentPassword("currentPassword");
    final PasswordHistory passwordHistory = new PasswordHistory();
    passwordHistory.setUserId(1);
    passwordHistory.setCurrentPassword("encodedCurrentPassword");
    when(jwtTokenProvider.getSubject(anyString())).thenReturn("1");
    when(jwtTokenProvider.getClaim("validToken", AppConstants.USER_STATUS)).thenReturn("ACTIVE");
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(
            changePasswordRequest.getCurrentPassword(), passwordHistory.getCurrentPassword()))
        .thenReturn(true);
    when(passwordEncoder.matches(
            changePasswordRequest.getPassword(), passwordHistory.getCurrentPassword()))
        .thenReturn(false);
    when(userService.findById(anyInt())).thenReturn(user);
    doNothing()
        .when(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
    authService.changePassword(changePasswordRequest, "validToken");
    verify(passwordHistoryRepository, times(1)).save(any(PasswordHistory.class));
  }

  @Test
  void changePassword_SuccessForInactiveStudent() throws ParseException {
    // Create a request with the current and new password
    final ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
    changePasswordRequest.setPassword("newPassword");
    changePasswordRequest.setCurrentPassword("currentPassword");
    final PasswordHistory passwordHistory = new PasswordHistory();
    passwordHistory.setUserId(1);
    passwordHistory.setCurrentPassword("encodedCurrentPassword");
    when(jwtTokenProvider.getSubject(anyString())).thenReturn("1");
    when(jwtTokenProvider.getClaim("validToken", AppConstants.USER_STATUS)).thenReturn("INACTIVE");
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(
            changePasswordRequest.getCurrentPassword(), passwordHistory.getCurrentPassword()))
        .thenReturn(true);
    when(passwordEncoder.matches(
            changePasswordRequest.getPassword(), passwordHistory.getCurrentPassword()))
        .thenReturn(false);
    user.setRole(UserRole.STUDENT);
    when(userService.findById(anyInt())).thenReturn(user);
    doNothing()
        .when(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
    doNothing().when(userService).updateUser(1, 1, Map.of("status", UserStatus.ACTIVE.toString()));
    authService.changePassword(changePasswordRequest, "validToken");
    verify(passwordHistoryRepository, times(1)).save(any(PasswordHistory.class));
    verify(userService, times(1)).updateUser(1, 1, Map.of("status", UserStatus.ACTIVE.toString()));
  }

  @Test
  void changePassword_SuccessForInactiveStudentFirstLogin() throws ParseException {
    // Create a request with the current and new password
    final ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
    changePasswordRequest.setPassword("newPassword");
    changePasswordRequest.setCurrentPassword("currentPassword");
    final PasswordHistory passwordHistory = new PasswordHistory();
    passwordHistory.setUserId(1);
    passwordHistory.setCurrentPassword("encodedCurrentPassword");
    when(jwtTokenProvider.getSubject(anyString())).thenReturn("1");
    when(jwtTokenProvider.getClaim("validToken", AppConstants.USER_STATUS)).thenReturn("INACTIVE");
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(
            changePasswordRequest.getCurrentPassword(), passwordHistory.getCurrentPassword()))
        .thenReturn(true);
    when(passwordEncoder.matches(
            changePasswordRequest.getPassword(), passwordHistory.getCurrentPassword()))
        .thenReturn(false);
    user.setRole(UserRole.STUDENT);
    user.setFirstLogin(true);
    when(userService.findById(anyInt())).thenReturn(user);
    doNothing().when(userService).updateUser(anyInt(), anyInt(), any(User.class));
    doNothing()
        .when(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
    doNothing().when(userService).updateUser(1, 1, Map.of("status", UserStatus.ACTIVE.toString()));
    authService.changePassword(changePasswordRequest, "validToken");
    verify(passwordHistoryRepository, times(1)).save(any(PasswordHistory.class));
    verify(userService, times(1)).updateUser(1, 1, Map.of("status", UserStatus.ACTIVE.toString()));
    verify(userService, times(1)).updateUser(1, 1, user);
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
    when(jwtTokenProvider.getClaim("validToken", AppConstants.USER_STATUS)).thenReturn("ACTIVE");
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
    when(jwtTokenProvider.getClaim("validToken", AppConstants.USER_STATUS)).thenReturn("ACTIVE");
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
    // when(passwordHistoryRepository.save(any())).thenReturn(user);
    assertThrows(
        GlobalExceptionHandler.SamePasswordException.class,
        () -> authService.changePassword(changePasswordRequest, "validToken"));
  }

  @Test
  void changePassword_ActiveUserAndNoCurrentPassword() throws ParseException {
    ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
    changePasswordRequest.setPassword("encodedPassword");
    changePasswordRequest.setCurrentPassword("");

    PasswordHistory passwordHistory = new PasswordHistory();
    passwordHistory.setUserId(1);
    passwordHistory.setCurrentPassword("encodedPassword");

    when(jwtTokenProvider.getSubject(anyString())).thenReturn("1");
    when(jwtTokenProvider.getClaim("validToken", AppConstants.USER_STATUS)).thenReturn("ACTIVE");
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
    // when(passwordHistoryRepository.save(any())).thenReturn(user);
    doNothing()
        .when(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
    assertThrows(
        GlobalExceptionHandler.GenericException.class,
        () -> authService.changePassword(changePasswordRequest, "validToken"));
  }

  @Test
  void changePassword_NoCurrentPasswordProvided() throws ParseException {
    ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
    changePasswordRequest.setPassword("newPassword");

    PasswordHistory passwordHistory = new PasswordHistory();
    passwordHistory.setUserId(1);
    passwordHistory.setCurrentPassword("encodedPassword");
    when(jwtTokenProvider.getClaim("validToken", AppConstants.USER_STATUS)).thenReturn("INACTIVE");
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
  void resetPassword_SamePasswordException() {
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
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
    assertThrows(
        GlobalExceptionHandler.SamePasswordException.class,
        () -> authService.resetPasswordSelf(resetPasswordRequest));
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

  @Test
  void getLoginHistory_WhenHistoryExists_ShouldReturnLastTenEntries() {
    final LoginHistory loginHistory1 = new LoginHistory();
    loginHistory1.setId(1L);
    loginHistory1.setUserId(1);
    loginHistory1.setLastLoginTime(LocalDateTime.now());
    loginHistory1.setIpAddress("192.168.1.1");

    final LoginHistory loginHistory2 = new LoginHistory();
    loginHistory2.setId(2L);
    loginHistory2.setUserId(1);
    loginHistory2.setLastLoginTime(LocalDateTime.now().minusHours(1));
    loginHistory2.setIpAddress("192.168.1.2");

    // Given
    final List<LoginHistory> historyList = List.of(loginHistory1, loginHistory2);
    final Page<LoginHistory> historyPage = new PageImpl<>(historyList);

    when(loginHistoryRepository.findAllByUserId(eq(1), any(PageRequest.class)))
        .thenReturn(historyPage);

    // When
    List<LoginHistoryResponse> result = authService.getLoginHistory(1);

    // Then
    assertNotNull(result);
    assertEquals(2, result.size());
    verify(loginHistoryRepository)
        .findAllByUserId(
            eq(1),
            argThat(
                pageRequest ->
                    pageRequest.getPageNumber() == 0
                        && pageRequest.getPageSize() == 10
                        && pageRequest.getSort().isSorted()));
  }

  @Test
  void getLoginHistory_WhenNoHistory_ShouldReturnEmptyList() {
    // Given
    Page<LoginHistory> emptyPage = new PageImpl<>(Collections.emptyList());
    when(loginHistoryRepository.findAllByUserId(eq(1), any(PageRequest.class)))
        .thenReturn(emptyPage);

    // When
    List<LoginHistoryResponse> result = authService.getLoginHistory(1);

    // Then
    assertNotNull(result);
    assertTrue(result.isEmpty());
  }

  @Test
  void getUserRoles_WhenUsersHaveRoles_ShouldReturnRoleMap() {
    // Given
    List<Integer> userIds = Arrays.asList(1, 2);
    List<Map<String, Object>> repositoryResponse =
        Arrays.asList(createUserRoleMap(1, "ADMIN"), createUserRoleMap(2, "USER"));

    when(passwordHistoryRepository.findUserRoleByUserIds(userIds)).thenReturn(repositoryResponse);

    // When
    Map<Integer, String> result = authService.getUserRoles(userIds);

    // Then
    assertNotNull(result);
    assertEquals(2, result.size());
    assertEquals("ADMIN", result.get(1));
    assertEquals("USER", result.get(2));
  }

  @Test
  void getUserRoles_WhenSomeUsersHaveNoRoles_ShouldReturnUnknown() {
    // Given
    List<Integer> userIds = Arrays.asList(1, 2, 3);
    List<Map<String, Object>> repositoryResponse =
        Arrays.asList(createUserRoleMap(1, "ADMIN"), createUserRoleMap(2, "USER"));

    when(passwordHistoryRepository.findUserRoleByUserIds(userIds)).thenReturn(repositoryResponse);

    // When
    Map<Integer, String> result = authService.getUserRoles(userIds);

    // Then
    assertNotNull(result);
    assertEquals(3, result.size());
    assertEquals("ADMIN", result.get(1));
    assertEquals("USER", result.get(2));
    assertEquals("UNKNOWN", result.get(3));
  }

  @Test
  void getUserRoles_WhenNoUsersFound_ShouldReturnAllUnknown() {
    // Given
    List<Integer> userIds = Arrays.asList(1, 2);
    when(passwordHistoryRepository.findUserRoleByUserIds(userIds))
        .thenReturn(Collections.emptyList());

    // When
    Map<Integer, String> result = authService.getUserRoles(userIds);

    // Then
    assertNotNull(result);
    assertEquals(2, result.size());
    assertEquals("UNKNOWN", result.get(1));
    assertEquals("UNKNOWN", result.get(2));
  }

  @Test
  void getUserRoles_WithEmptyUserIdsList_ShouldReturnEmptyMap() {
    // Given
    List<Integer> userIds = Collections.emptyList();
    when(passwordHistoryRepository.findUserRoleByUserIds(anyList()))
        .thenReturn(Collections.emptyList());

    // When
    Map<Integer, String> result = authService.getUserRoles(userIds);

    // Then
    assertNotNull(result);
    assertTrue(result.isEmpty());
  }

  @Test
  void getUserRoles_WithNullUserIds_ShouldThrowException() {
    // When/Then
    assertThrows(NullPointerException.class, () -> authService.getUserRoles(null));
  }

  @Test
  void getUserRoles_WhenRepositoryThrowsException_ShouldPropagateException() {
    // Given
    List<Integer> userIds = Arrays.asList(1, 2);
    when(passwordHistoryRepository.findUserRoleByUserIds(userIds))
        .thenThrow(new RuntimeException("Database error"));

    // When/Then
    assertThrows(RuntimeException.class, () -> authService.getUserRoles(userIds));
  }

  private Map<String, Object> createUserRoleMap(Integer userId, String role) {
    Map<String, Object> map = new HashMap<>();
    map.put("userId", userId);
    map.put("userRole", role);
    return map;
  }

  @Test
  void testCreateNewUser() {
    final UserCreateRequest userCreateRequest = new UserCreateRequest();
    userCreateRequest.setUserId(1);
    userCreateRequest.setPassword("password");
    userCreateRequest.setRole(UserRole.STUDENT);

    when(passwordHistoryRepository.save(Mockito.any(PasswordHistory.class)))
        .thenReturn(passwordHistory);

    authService.createNewUser(userCreateRequest);
    verify(passwordHistoryRepository, times(1)).save(Mockito.any(PasswordHistory.class));
  }

  @Test
  void test_resetPasswordByAdmin_invalidRole() {
    final String token = "token";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    when(jwtTokenProvider.getClaim("token", AppConstants.USER_ROLE))
        .thenReturn(UserRole.TEACHER.name());
    assertThrows(
        GlobalExceptionHandler.InvalidUserStatus.class,
        () -> authService.resetPasswordByAdmin(new ResetPasswordRequest(), token));
  }

  @Test
  void test_resetPasswordByAdmin_userRoleIsRequired() {
    final String token = "token";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    when(jwtTokenProvider.getClaim("token", AppConstants.USER_ROLE))
        .thenReturn(UserRole.HELPDESKADMIN.name());
    final ResetPasswordRequest request = new ResetPasswordRequest();
    request.setBehalfOf(List.of(new UserIdAndRole(1, null)));
    assertThrows(
        GlobalExceptionHandler.ResetPasswordException.class,
        () -> authService.resetPasswordByAdmin(request, token));
  }

  @Test
  void test_resetPasswordByAdmin_userNotFound() {
    final String token = "token";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    when(jwtTokenProvider.getClaim("token", AppConstants.USER_ROLE))
        .thenReturn(UserRole.HELPDESKADMIN.name());
    final ResetPasswordRequest request = new ResetPasswordRequest();
    request.setBehalfOf(List.of(new UserIdAndRole(2, UserRole.STUDENT.name())));

    when(userService.getUserDetails(2, String.join("", UserRole.STUDENT.name().toLowerCase(), "s")))
        .thenReturn(Optional.empty());
    assertThrows(
        NoSuchElementException.class, () -> authService.resetPasswordByAdmin(request, token));
  }

  //   @Test
  //   void test_resetPasswordByAdmin_userIsLocked() {
  //     final String token = "token";
  //     when(jwtTokenProvider.getSubject(token)).thenReturn("1");
  //     when(jwtTokenProvider.getClaim("token", AppConstants.USER_ROLE))
  //         .thenReturn(UserRole.HELPDESKADMIN.name());
  //     final ResetPasswordRequest request = new ResetPasswordRequest();
  //     request.setBehalfOf(List.of(new UserIdAndRole(2, UserRole.STUDENT.name())));
  //     final UserDetails userDetails = new UserDetails();
  //     user.setStatus(UserStatus.LOCKED);
  //     userDetails.setUser(user);
  //     when(userService.getUserDetails(2, String.join("", UserRole.STUDENT.name().toLowerCase(),
  // "s")))
  //         .thenReturn(Optional.of(userDetails));
  //     assertThrows(
  //         GlobalExceptionHandler.ResetPasswordException.class,
  //         () -> authService.resetPasswordByAdmin(request, token));
  //   }

  @Test
  void test_resetPasswordByAdmin_userIsPrincipal_schoolIdDoesNotMatch() {
    final String token = "token";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    when(jwtTokenProvider.getClaim("token", AppConstants.USER_ROLE))
        .thenReturn(UserRole.PRINCIPAL.name());
    final ResetPasswordRequest request = new ResetPasswordRequest();
    request.setBehalfOf(List.of(new UserIdAndRole(2, UserRole.STUDENT.name())));
    final UserDetails userDetails = new UserDetails();
    user.setStatus(UserStatus.ACTIVE);
    user.setRole(UserRole.PRINCIPAL);
    userDetails.setUser(user);
    userDetails.setSchoolId(2);
    when(userService.getUserDetails(2, String.join("", UserRole.STUDENT.name().toLowerCase(), "s")))
        .thenReturn(Optional.of(userDetails));
    final SchoolDetails schoolDetails = new SchoolDetails();
    schoolDetails.setPrincipalUserId(30);
    when(schoolService.getSchoolDetails(2, true)).thenReturn(schoolDetails);
    assertThrows(
        GlobalExceptionHandler.ResetPasswordException.class,
        () -> authService.resetPasswordByAdmin(request, token));
  }

  @Test
  void test_resetPasswordByAdmin_userIsPrincipal_schoolIdDoesNotMatchForMultipleUsers() {
    final String token = "token";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    when(jwtTokenProvider.getClaim("token", AppConstants.USER_ROLE))
        .thenReturn(UserRole.PRINCIPAL.name());
    final ResetPasswordRequest request = new ResetPasswordRequest();
    request.setBehalfOf(
        List.of(
            new UserIdAndRole(2, UserRole.STUDENT.name()),
            new UserIdAndRole(2, UserRole.STUDENT.name())));
    final UserDetails userDetails = new UserDetails();
    user.setStatus(UserStatus.ACTIVE);
    user.setRole(UserRole.PRINCIPAL);
    userDetails.setUser(user);
    userDetails.setSchoolId(2);
    when(userService.getUserDetails(2, String.join("", UserRole.STUDENT.name().toLowerCase(), "s")))
        .thenReturn(Optional.of(userDetails));
    final SchoolDetails schoolDetails = new SchoolDetails();
    schoolDetails.setPrincipalUserId(30);
    when(schoolService.getSchoolDetails(2, true)).thenReturn(schoolDetails);
    assertThrows(
        GlobalExceptionHandler.ResetPasswordException.class,
        () -> authService.resetPasswordByAdmin(request, token));
  }

  @Test
  void test_resetPasswordByAdmin_userIsPrincipalAndPasswordHistoryIsEmpty() {
    final String token = "token";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    when(jwtTokenProvider.getClaim("token", AppConstants.USER_ROLE))
        .thenReturn(UserRole.PRINCIPAL.name());
    final ResetPasswordRequest request = new ResetPasswordRequest();
    request.setBehalfOf(List.of(new UserIdAndRole(2, UserRole.STUDENT.name())));
    final UserDetails userDetails = new UserDetails();
    user.setStatus(UserStatus.ACTIVE);
    user.setRole(UserRole.PRINCIPAL);
    userDetails.setUser(user);
    userDetails.setSchoolId(2);
    when(userService.getUserDetails(2, String.join("", UserRole.STUDENT.name().toLowerCase(), "s")))
        .thenReturn(Optional.of(userDetails));
    final SchoolDetails schoolDetails = new SchoolDetails();
    schoolDetails.setPrincipalUserId(1);
    when(schoolService.getSchoolDetails(2, true)).thenReturn(schoolDetails);
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of()));

    assertThrows(
        GlobalExceptionHandler.ResetPasswordException.class,
        () -> authService.resetPasswordByAdmin(request, token));
  }

  @Test
  void test_resetPasswordByAdmin_userIsPrincipalAndPasswordHistoryIsNotEmpty() {
    final String token = "token";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    when(jwtTokenProvider.getClaim("token", AppConstants.USER_ROLE))
        .thenReturn(UserRole.PRINCIPAL.name());
    final ResetPasswordRequest request = new ResetPasswordRequest();
    request.setBehalfOf(List.of(new UserIdAndRole(2, UserRole.STUDENT.name())));
    final UserDetails userDetails = new UserDetails();
    user.setStatus(UserStatus.ACTIVE);
    user.setRole(UserRole.PRINCIPAL);
    user.setFullName("Test User");
    user.setDateOfBirth(java.sql.Date.valueOf(LocalDate.now()));
    user.setMobile(null);
    userDetails.setUser(user);
    userDetails.setSchoolId(2);
    when(userService.getUserDetails(2, String.join("", UserRole.STUDENT.name().toLowerCase(), "s")))
        .thenReturn(Optional.of(userDetails));
    final SchoolDetails schoolDetails = new SchoolDetails();
    schoolDetails.setPrincipalUserId(1);
    schoolDetails.setSchoolUdiseCode("123");
    when(schoolService.getSchoolDetails(2, true)).thenReturn(schoolDetails);
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));

    doNothing()
        .when(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
    when(passwordHistoryRepository.saveAll(anyList())).thenReturn(List.of(passwordHistory));
    authService.resetPasswordByAdmin(request, token);
    verify(notificationService, times(1))
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
    verify(passwordHistoryRepository, times(1)).saveAll(anyList());
  }

  @Test
  void test_resetPasswordByAdmin_userIsPrincipalAndPasswordHistoryIsNotEmptyAndEmailIsEmpty() {
    final String token = "token";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    when(jwtTokenProvider.getClaim("token", AppConstants.USER_ROLE))
        .thenReturn(UserRole.HELPDESKADMIN.name());
    final ResetPasswordRequest request = new ResetPasswordRequest();
    request.setBehalfOf(List.of(new UserIdAndRole(2, UserRole.TEACHER.name())));
    final UserDetails userDetails = new UserDetails();
    user.setStatus(UserStatus.ACTIVE);
    user.setRole(UserRole.PRINCIPAL);
    user.setEmail("");
    user.setFullName("Test User");
    user.setDateOfBirth(null);
    user.setMobile("1234567890");
    userDetails.setUser(user);
    userDetails.setSchoolId(2);
    when(userService.getUserDetails(2, String.join("", UserRole.TEACHER.name().toLowerCase(), "s")))
        .thenReturn(Optional.of(userDetails));
    final SchoolDetails schoolDetails = new SchoolDetails();
    schoolDetails.setPrincipalUserId(1);
    schoolDetails.setSchoolUdiseCode("12345");
    when(schoolService.getSchoolDetails(2, true)).thenReturn(schoolDetails);
    when(passwordHistoryRepository.findAllByUserId(anyInt(), any(PageRequest.class)))
        .thenReturn(new PageImpl<>(List.of(passwordHistory)));

    doNothing()
        .when(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
    when(passwordHistoryRepository.saveAll(anyList())).thenReturn(List.of(passwordHistory));
    authService.resetPasswordByAdmin(request, token);
    verify(notificationService, times(0))
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
  }
}
