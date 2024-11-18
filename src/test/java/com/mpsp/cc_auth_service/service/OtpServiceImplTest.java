package com.mpsp.cc_auth_service.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.entity.OtpGen;
import com.mpsp.cc_auth_service.feignclients.UserServiceClient;
import com.mpsp.cc_auth_service.repository.OtpGenRepo;
import com.mpsp.cc_auth_service.service.impl.OtpServiceImpl;
import com.mpsp.cc_auth_service.utils.JwtTokenProvider;
import java.time.LocalDateTime;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ActiveProfiles("dev")
@ContextConfiguration(classes = {OtpServiceImpl.class})
public class OtpServiceImplTest {

  @Autowired private OtpServiceImpl otpService;

  @MockBean private UserServiceClient userService;

  @MockBean private OtpGenRepo otpGenRepo;

  @MockBean private NotificationService notificationService;

  @MockBean private JwtTokenProvider jwtTokenProvider;

  @Test
  public void testSendOtp_UserFound() {
    User user = new User();
    user.setUserId(1);
    user.setEmail("test@example.com");
    when(userService.findByEmail("test@example.com")).thenReturn(user);
    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.empty());
    doNothing().when(notificationService).sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());

    final String otp = otpService.sendOtp("test@example.com");
    assertNotNull(otp);
    verify(notificationService, times(1)).sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
    verify(otpGenRepo, times(1)).saveAndFlush(any(OtpGen.class));
  }

  //    @Test
  //    public void testVerifyOtp_UserNotFound() {
  //        when(userService.findByEmail(anyString())).thenReturn(null);
  //        assertThrows(UsernameNotFoundException.class, () ->
  // otpService.verifyOtp("test@example.com", "1234"));
  //    }
  //
  //    @Test
  //    public void testVerifyOtp_OtpExpired() {
  //        User user = new User();
  //        user.setUserId(1);
  //        OtpGen otpGen = new OtpGen();
  //        otpGen.setModifiedAt(LocalDateTime.now().minusHours(2));
  //        when(userService.findByEmail(anyString())).thenReturn(user);
  //        when(otpGenRepo.findByUserId(anyInt())).thenReturn(otpGen);
  //
  //        assertThrows(RuntimeException.class, () -> otpService.verifyOtp("test@example.com",
  // "1234"));
  //    }
  //
  //    @Test
  //    public void testVerifyOtp_ValidOtp() throws ParseException {
  //        User user = new User();
  //        user.setUserId(1);
  //        OtpGen otpGen = new OtpGen();
  //        otpGen.setModifiedAt(LocalDateTime.now());
  //        otpGen.setOtp("1234");
  //        when(userService.findByEmail(anyString())).thenReturn(user);
  //        when(otpGenRepo.findByUserId(anyInt())).thenReturn(otpGen);
  //
  //        assertTrue(otpService.verifyOtp("test@example.com", "1234"));
  //    }

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
    doNothing().when(notificationService).sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());

    // Call the method under test
    otpService.resendOtp(dummyToken);

    // Verify interactions
    verify(jwtTokenProvider).getUserEmail(dummyToken);
    verify(userService).findByEmail("dummy@example.com");
    verify(notificationService)
        .sendNotification(anyString(), anyString(), anyString(), anyString(), anyMap());
    verify(otpGenRepo).saveAndFlush(any(OtpGen.class));
  }
}
