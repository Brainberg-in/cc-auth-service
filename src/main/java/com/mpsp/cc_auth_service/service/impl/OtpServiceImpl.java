package com.mpsp.cc_auth_service.service.impl;

import com.mpsp.cc_auth_service.constants.UserStatus;
import com.mpsp.cc_auth_service.dto.SendOtp;
import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.dto.VerifyOtp;
import com.mpsp.cc_auth_service.entity.OtpGen;
import com.mpsp.cc_auth_service.feignclients.UserServiceClient;
import com.mpsp.cc_auth_service.repository.OtpGenRepo;
import com.mpsp.cc_auth_service.service.NotificationService;
import com.mpsp.cc_auth_service.service.OtpService;
import com.mpsp.cc_auth_service.utils.GeneratorUtils;
import com.mpsp.cc_auth_service.utils.GlobalExceptionHandler.OTPExpiredException;
import com.mpsp.cc_auth_service.utils.GlobalExceptionHandler.OTPVerificationException;
import com.mpsp.cc_auth_service.utils.JwtTokenProvider;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
public class OtpServiceImpl implements OtpService {

  @Autowired private transient UserServiceClient userService;

  @Autowired private transient OtpGenRepo otpGenRepo;

  @Autowired private transient JwtTokenProvider jwtTokenProvider;

  @Autowired private transient NotificationService notificationService;

  @Value("${spring.profiles.active}")
  private String activeProfile;

  @Value("${aws.ses.sender}")
  private String senderEmail;

  private String generateOTP(final int userId) {
    final String otp =
        List.of("dev", "staging").contains(activeProfile) ? "1234" : GeneratorUtils.generateOTP(4);
    otpGenRepo
        .findByUserId(userId)
        .ifPresentOrElse(
            otpGen -> {
              otpGen.setModifiedAt(LocalDateTime.now());
              otpGen.setOtp(otp);
              otpGenRepo.save(otpGen);
            },
            () -> {
              final OtpGen otpGen = new OtpGen();
              otpGen.setUserId(userId);
              otpGen.setOtp(otp);
              otpGen.setCreatedAt(LocalDateTime.now());
              otpGen.setModifiedAt(LocalDateTime.now());
              otpGenRepo.save(otpGen);
            });
    return otp;
  }

  @Override
  @Transactional
  public String sendOtp(final String email) {
    final User user = userService.findByEmail(email);
    final String otp = generateOTP(user.getUserId());

    notificationService.sendNotification("email", "login_cc_otp", email, "", Map.of("otp", otp));
    return otp;
  }

  @Override
  @Transactional
  public void sendVerificationOtp(String token, SendOtp sendOtp) {
    final String userEmail = jwtTokenProvider.getUserEmail(token);
    if (userEmail == null) {
      throw new IllegalArgumentException("User does not have a registered email");
    }
    if (sendOtp.getMode().equals("sms") && List.of("dev", "staging").contains(activeProfile)) {
      return;
    }
    final User user = userService.findByEmail(userEmail);
    final String mobile = user.getMobile();

    Map<String, String> dataMap = new HashMap<>();

    final String otp = generateOTP(user.getUserId());
    dataMap.put("otp", otp);

    notificationService.sendNotification(
        sendOtp.getMode(), "verification_otp", userEmail, mobile, dataMap);
  }

  @Override
  public boolean verifyOtp(final String token, final String otp) {
    final int userId = Integer.parseInt(jwtTokenProvider.getSubject(token));

    if (userId == 0) {
      throw new NoSuchElementException("User not found");
    }

    return otpGenRepo
        .findByUserId(userId)
        .map(
            otpGen -> {
              if (otpGen.getModifiedAt().isBefore(LocalDateTime.now().minusHours(1))) {
                throw new OTPExpiredException("OTP expired");
              }
              if (!otpGen.getOtp().equals(otp)) {
                throw new OTPVerificationException("OTP verification failed");
              }
              return true;
            })
        .orElseThrow(() -> new NoSuchElementException("OTP not found for user"));
  }

  @Override
  public boolean validate(final String token, final VerifyOtp verifyOtp) {
    final int userId = Integer.parseInt(jwtTokenProvider.getSubject(token));

    if (userId == 0) {
      throw new NoSuchElementException("User not found");
    }

    return otpGenRepo
        .findByUserId(userId)
        .map(
            otpGen -> {
              if (otpGen.getModifiedAt().isBefore(LocalDateTime.now().minusHours(1))) {
                throw new OTPExpiredException("OTP expired");
              }
              if (!otpGen.getOtp().equals(verifyOtp.getOtp())) {
                throw new OTPVerificationException("OTP verification failed");
              }
              if ("verification".equals(verifyOtp.getPurpose())) {
                verifyUser(userId, verifyOtp.getMode());
              }
              return true;
            })
        .orElseThrow(() -> new NoSuchElementException("OTP not found for user"));
  }

  private void verifyUser(int userId, String mode) {
    final User userDetails = userService.findById(userId);
    final Map<String, Boolean> userDataMap = new HashMap<>();
    log.info("userData: {}", userDetails);

    if (mode.equals("email")) {
      userDetails.setEmailVerified(true);
      userDataMap.put("isEmailVerified", true);
    } else if (mode.equals("sms")) {
      userDetails.setMobileVerified(true);
      userDataMap.put("isMobileVerified", true);
    }
    userService.updateUserVerification(userId, userDataMap);
    if (userDetails.isEmailVerified() && userDetails.isMobileVerified()) {
      log.info("Updating User status to ACTIVE");
      final Map<String, String> userStatusDataMap = Map.of("status", UserStatus.ACTIVE.toString());
      userService.updateUserStatus(userId, userStatusDataMap);
      log.info("User status updated to ACTIVE");
    }
    log.info("User verified successfully");
  }

  @Override
  @Transactional
  public void resendOtp(String token) {
    final String userEmail = jwtTokenProvider.getUserEmail(token);
    if (userEmail == null) {
      log.error("User does not have a registered email");
      throw new IllegalArgumentException("User does not have a registered email");
    }

    final User user = userService.findByEmail(userEmail);

    notificationService.sendNotification(
        "email", "login_cc_otp", userEmail, "", Map.of("otp", generateOTP(user.getUserId())));
  }
}
