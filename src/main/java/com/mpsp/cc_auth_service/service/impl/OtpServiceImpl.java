package com.mpsp.cc_auth_service.service.impl;

import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.entity.OtpGen;
import com.mpsp.cc_auth_service.feignclients.UserServiceClient;
import com.mpsp.cc_auth_service.repository.OtpGenRepo;
import com.mpsp.cc_auth_service.service.AwsService;
import com.mpsp.cc_auth_service.service.OtpService;
import com.mpsp.cc_auth_service.utils.GeneratorUtils;
import com.mpsp.cc_auth_service.utils.JwtTokenProvider;
import com.mpsp.cc_auth_service.utils.GlobalExceptionHandler.OTPExpiredException;
import com.mpsp.cc_auth_service.utils.GlobalExceptionHandler.OTPVerificationException;

import java.time.LocalDateTime;
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

  @Autowired private transient AwsService awsService;

  @Autowired private transient JwtTokenProvider jwtTokenProvider;

  @Value("${spring.profiles.active}")
  private String activeProfile;

  @Value("${aws.ses.sender}")
  private String senderEmail;

  private String generateOTP(final int userId) {
    final String otp = GeneratorUtils.generateOTP(4);
    otpGenRepo
        .findByUserId(userId)
        .ifPresentOrElse(
            otpGen -> {
              otpGen.setModifiedAt(LocalDateTime.now());
              otpGen.setOtp(otp);
              otpGenRepo.saveAndFlush(otpGen);
            },
            () -> {
              final OtpGen otpGen = new OtpGen();
              otpGen.setUserId(userId);
              otpGen.setOtp(otp);
              otpGen.setCreatedAt(LocalDateTime.now());
              otpGen.setModifiedAt(LocalDateTime.now());
              otpGenRepo.saveAndFlush(otpGen);
            });
    return otp;
  }

  @Override
  @Transactional
  public String sendOtp(final String email) {
    final User user = userService.findByEmail(email);
    final String otp = generateOTP(user.getUserId());
    awsService.sendEmail(senderEmail, email, "login_cc_otp", Map.of("otp", otp));
    return otp;
  }

  @Override
public boolean verifyOtp(final String token, final String otp) {
    final int userId = Integer.parseInt(jwtTokenProvider.getSubject(token));

    if (userId == 0) {
        throw new NoSuchElementException("User not found");
    }

    return otpGenRepo
        .findByUserId(userId)
        .map(otpGen -> {
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
  @Transactional
  public void resendOtp(String token) {
    final String userEmail = jwtTokenProvider.getUserEmail(token);
    if (userEmail == null) {
      throw new IllegalArgumentException("User does not have a registered email");
    }

    final User user = userService.findByEmail(userEmail);

    awsService.sendEmail(
        senderEmail, userEmail, "login_cc_otp", Map.of("otp", generateOTP(user.getUserId())));
  }
}
