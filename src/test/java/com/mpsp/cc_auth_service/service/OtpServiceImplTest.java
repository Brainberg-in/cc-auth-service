package com.mpsp.cc_auth_service.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import com.mpsp.cc_auth_service.constants.UserStatus;
import com.mpsp.cc_auth_service.dto.SendOtp;
import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.dto.VerifyOtp;
import com.mpsp.cc_auth_service.entity.OtpGen;
import com.mpsp.cc_auth_service.feignclients.UserServiceClient;
import com.mpsp.cc_auth_service.repository.OtpGenRepo;
import com.mpsp.cc_auth_service.service.impl.OtpServiceImpl;
import com.mpsp.cc_auth_service.utils.GlobalExceptionHandler.OTPExpiredException;
import com.mpsp.cc_auth_service.utils.GlobalExceptionHandler.OTPVerificationException;
import com.mpsp.cc_auth_service.utils.JwtTokenProvider;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ActiveProfiles("dev")
@ContextConfiguration(classes = {OtpServiceImpl.class})
@TestPropertySource(
    properties = {"spring.profiles.active=dev"},
    locations = {"classpath:application.properties", "classpath:application-dev.properties"})
public class OtpServiceImplTest {

  @Autowired private OtpServiceImpl otpService;

  @MockitoBean private UserServiceClient userService;

  @MockitoBean private OtpGenRepo otpGenRepo;

  @MockitoBean private NotificationService notificationService;

  @MockitoBean private JwtTokenProvider jwtTokenProvider;

  @Test
  public void testSendOtp_UserFound() {
    final User user = new User();
    user.setUserId(1);
    user.setEmail("test@example.com");
    when(userService.findByEmail("test@example.com")).thenReturn(user);
    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.empty());
    doNothing()
        .when(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());

    final String otp = otpService.sendOtp("test@example.com");
    assertNotNull(otp);
    verify(notificationService, times(1))
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
    verify(otpGenRepo, times(1)).save(any(OtpGen.class));
  }

  @Test
  public void testSendVerificationOtpWhenEmailNotFound() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getUserEmail(token)).thenReturn(null);

    assertThrows(IllegalArgumentException.class, () -> otpService.sendVerificationOtp(token, null));
  }

  @Test
  public void testSendVerificationOtp() {
    final String token = "TOKEN";
    final User user = new User();
    user.setUserId(1);
    user.setEmail("test@example.com");
    user.setMobile("1234567890");
    when(jwtTokenProvider.getUserEmail(token)).thenReturn("test@example.com");
    when(userService.findByEmail("test@example.com")).thenReturn(user);
    doNothing()
        .when(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());

    final SendOtp sendOtp = new SendOtp();
    sendOtp.setMode("email");
    otpService.sendVerificationOtp(token, sendOtp);
    verify(notificationService, times(1))
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
  }

  @Test
  public void testSendVerificationOtpWhenModeIsSms() {
    final String token = "TOKEN";
    final User user = new User();
    user.setUserId(1);
    user.setEmail("test@example.com");
    user.setMobile("1234567890");
    when(jwtTokenProvider.getUserEmail(token)).thenReturn("test@example.com");
    when(userService.findByEmail("test@example.com")).thenReturn(user);
    doNothing().when(notificationService).sendNotification(any(), any(), any(), any(), any());

    final SendOtp sendOtp = new SendOtp();
    sendOtp.setMode("sms");
    otpService.sendVerificationOtp(token, sendOtp);
    verify(notificationService, times(0)).sendNotification(any(), any(), any(), any(), any());
  }

  @Test
  public void testVerifyOtp_UserNotFound() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getSubject(token)).thenReturn("0");

    assertThrows(NoSuchElementException.class, () -> otpService.verifyOtp(token, "1234"));
  }

  @Test
  public void testVerifyOtp_OtpNotFound() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");

    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.empty());

    assertThrows(NoSuchElementException.class, () -> otpService.verifyOtp(token, "1234"));
  }

  @Test
  public void testVerifyOtp_OtpExpired() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    final OtpGen otpGen = new OtpGen();

    otpGen.setModifiedAt(LocalDateTime.now().minusHours(2));

    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.of(otpGen));

    assertThrows(OTPExpiredException.class, () -> otpService.verifyOtp(token, "1234"));
  }

  @Test
  public void testVerifyOtp_InvalidOtp() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    final OtpGen otpGen = new OtpGen();
    otpGen.setOtp("1235");

    otpGen.setModifiedAt(LocalDateTime.now().minusMinutes(30));

    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.of(otpGen));

    assertThrows(OTPVerificationException.class, () -> otpService.verifyOtp(token, "1234"));
  }

  @Test
  public void testVerifyOtp_ValidOtp() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    final OtpGen otpGen = new OtpGen();
    otpGen.setOtp("1234");

    otpGen.setModifiedAt(LocalDateTime.now().minusMinutes(30));

    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.of(otpGen));

    assertTrue(otpService.verifyOtp(token, "1234"));
  }

  @Test
  public void testValidate_UserNotFound() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getSubject(token)).thenReturn(null);

    assertThrows(IllegalArgumentException.class, () -> otpService.validate(token, null));
  }

  @Test
  public void testValidate_OtpNotFound() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");

    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.empty());

    assertThrows(NoSuchElementException.class, () -> otpService.validate(token, null));
  }

  @Test
  public void testValidate_OtpExpired() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    final OtpGen otpGen = new OtpGen();

    otpGen.setModifiedAt(LocalDateTime.now().minusHours(2));

    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.of(otpGen));

    assertThrows(OTPExpiredException.class, () -> otpService.validate(token, null));
  }

  @Test
  public void testValidate_OtpNotValid() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    final OtpGen otpGen = new OtpGen();
    otpGen.setOtp("1234");
    otpGen.setModifiedAt(LocalDateTime.now().minusMinutes(30));

    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.of(otpGen));

    final VerifyOtp verifyOtp = new VerifyOtp();
    verifyOtp.setOtp("1235");
    assertThrows(OTPVerificationException.class, () -> otpService.validate(token, verifyOtp));
  }

  @Test
  public void testValidate_OtpNotVerificationPurpose() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    final OtpGen otpGen = new OtpGen();
    otpGen.setOtp("1234");
    otpGen.setModifiedAt(LocalDateTime.now().minusMinutes(30));

    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.of(otpGen));

    final VerifyOtp verifyOtp = new VerifyOtp();
    verifyOtp.setOtp("1234");
    assertTrue(otpService.validate(token, verifyOtp));
  }

  @Test
  public void testValidate_EmailOtpValid() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    final OtpGen otpGen = new OtpGen();
    otpGen.setOtp("1234");
    otpGen.setModifiedAt(LocalDateTime.now().minusMinutes(30));

    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.of(otpGen));

    final VerifyOtp verifyOtp = new VerifyOtp();
    verifyOtp.setOtp("1234");
    verifyOtp.setMode("email");
    verifyOtp.setPurpose("verification");
    final User user = new User();
    user.setUserId(1);
    user.setEmail("test@example.com");
    when(userService.findById(1)).thenReturn(user);
    final Map<String, Object> userDataMap = Map.of("isEmailVerified", true);
    doNothing().when(userService).updateUser(null, null);
    assertTrue(otpService.validate(token, verifyOtp));
    verify(userService, times(1)).updateUser(1, userDataMap);
  }

  @Test
  public void testValidate_SmsOtpValid() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getSubject(token)).thenReturn("1");
    final OtpGen otpGen = new OtpGen();
    otpGen.setOtp("1234");
    otpGen.setModifiedAt(LocalDateTime.now().minusMinutes(30));

    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.of(otpGen));

    final VerifyOtp verifyOtp = new VerifyOtp();
    verifyOtp.setOtp("1234");
    verifyOtp.setMode("sms");
    verifyOtp.setPurpose("verification");
    final User user = new User();
    user.setUserId(1);
    user.setEmail("test@example.com");
    user.setMobile("1234567890");
    user.setEmailVerified(true);
    when(userService.findById(1)).thenReturn(user);
    final Map<String, Object> userDataMap = Map.of("isMobileVerified", true);
    doNothing().when(userService).updateUser(1, userDataMap);
    final Map<String, Object> userStatusDataMap = Map.of("status", UserStatus.ACTIVE.toString());
    doNothing().when(userService).updateUser(anyInt(), anyMap());
    assertTrue(otpService.validate(token, verifyOtp));
    verify(userService, times(1)).updateUser(1, userDataMap);
    verify(userService, times(1)).updateUser(1, userStatusDataMap);
  }

  @Test
  public void testResendOtp_UserNotFound() {
    final String token = "TOKEN";
    when(jwtTokenProvider.getUserEmail(token)).thenReturn(null);

    assertThrows(IllegalArgumentException.class, () -> otpService.resendOtp(token));
  }

  @Test
  public void testResendOtp_UserFound() {
    final User user = new User();
    user.setUserId(1);
    user.setEmail("dummy@example.com");

    // Mock JWT token provider
    String dummyToken = "jwtToken";
    when(jwtTokenProvider.getUserEmail(dummyToken)).thenReturn("dummy@example.com");

    when(userService.findByEmail("dummy@example.com")).thenReturn(user);

    final OtpGen otpGen = new OtpGen();
    otpGen.setModifiedAt(LocalDateTime.now());
    otpGen.setOtp("1234");
    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.of(otpGen));
    doNothing()
        .when(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());

    // Call the method under test
    otpService.resendOtp(dummyToken);

    // Verify interactions
    verify(jwtTokenProvider).getUserEmail(dummyToken);
    verify(userService).findByEmail("dummy@example.com");
    verify(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
    verify(otpGenRepo).save(any(OtpGen.class));
  }
}
