package com.mpsp.cc_auth_service.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.entity.OtpGen;
import com.mpsp.cc_auth_service.feignclients.UserServiceClient;
import com.mpsp.cc_auth_service.repository.OtpGenRepo;
import com.mpsp.cc_auth_service.service.impl.OtpServiceImpl;
import com.mpsp.cc_auth_service.utils.JwtTokenProvider;
import java.time.LocalDateTime;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class OtpServiceImplTest {

  @InjectMocks private OtpServiceImpl otpService;

  @Mock private UserServiceClient userService;

  @Mock private OtpGenRepo otpGenRepo;

  @Mock private AwsService awsService;

  @Mock private JwtTokenProvider jwtTokenProvider;

  @BeforeEach
  public void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  public void testSendOtp_UserFound() {
    User user = new User();
    user.setUserId(1);
    when(userService.findByEmail(anyString())).thenReturn(user);
    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.empty());
    doNothing().when(awsService).sendEmail(anyString(), anyString(), anyString(), anyMap());

    String otp = otpService.sendOtp("test@example.com");
    assertNotNull(otp);
    verify(awsService, times(1)).sendEmail(anyString(), anyString(), anyString(), anyMap());
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
    User user = new User();
    user.setUserId(1);
    OtpGen otpGen = new OtpGen();
    otpGen.setModifiedAt(LocalDateTime.now());
    otpGen.setOtp("1234");
    when(userService.findByEmail(anyString())).thenReturn(user);
    when(otpGenRepo.findByUserId(anyInt())).thenReturn(Optional.of(otpGen));
    doNothing().when(awsService).sendEmail(anyString(), anyString(), anyString(), anyMap());

    otpService.resendOtp("test@example.com");
    verify(awsService, times(1)).sendEmail(anyString(), anyString(), anyString(), anyMap());
    verify(otpGenRepo, times(1)).saveAndFlush(any(OtpGen.class));
  }
}
