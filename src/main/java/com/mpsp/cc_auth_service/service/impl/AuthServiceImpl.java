package com.mpsp.cc_auth_service.service.impl;

import com.mpsp.cc_auth_service.dto.LoginRequest;
import com.mpsp.cc_auth_service.dto.LoginResponse;
import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.entity.LoginHistory;
import com.mpsp.cc_auth_service.entity.PasswordHistory;
import com.mpsp.cc_auth_service.entity.RefreshToken;
import com.mpsp.cc_auth_service.feignclients.UserServiceClient;
import com.mpsp.cc_auth_service.repository.LoginHistoryRepo;
import com.mpsp.cc_auth_service.repository.PasswordHistoryRepo;
import com.mpsp.cc_auth_service.repository.RefreshTokenRepo;
import com.mpsp.cc_auth_service.service.AuthService;
import com.mpsp.cc_auth_service.service.OtpService;
import com.mpsp.cc_auth_service.utils.JwtTokenProvider;
import java.time.LocalDateTime;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class AuthServiceImpl implements AuthService {

  @Autowired private transient UserServiceClient userService;

  @Autowired private transient PasswordEncoder passwordEncoder;

  @Autowired private transient JwtTokenProvider jwtTokenProvider;

  @Autowired private transient LoginHistoryRepo loginHistoryRepository;

  @Autowired private transient PasswordHistoryRepo passwordHistoryRepository;

  @Autowired private transient RefreshTokenRepo refreshTokenRepository;

  @Autowired private transient OtpService otpService;

  @Override
  public LoginResponse login(final LoginRequest loginRequest) {
    final String email = loginRequest.getEmail();
    final String password = loginRequest.getPassword();

    // Validate user and password
    final User user = userService.findByEmail(email);
    if (user == null) {
      throw new UsernameNotFoundException("User not found");
    }

    System.out.println(user.getUserId());

    PasswordHistory pw = passwordHistoryRepository.findByUserId(user.getUserId());
    System.out.println(pw.getCurrentPassword());

    if (!passwordEncoder.matches(password, pw.getCurrentPassword())) {
      throw new BadCredentialsException("Invalid password");
    }

    // Generate tokens
    final String jwtToken = jwtTokenProvider.generateToken(user, false);
    final String refreshToken = jwtTokenProvider.generateToken(user, true);
    saveRefreshToken(user.getUserId(), refreshToken);

    System.out.println("Login successful" + jwtToken);

    // Create records in the history tables
    loginHistoryRepository.save(new LoginHistory(user.getUserId(), LocalDateTime.now()));

    String otp = null;
    if (user.isMfaEnabled()) {
      otpService.sendOtp(email); // Send OTP via AWS SES/SNS
    }

    return new LoginResponse(jwtToken, refreshToken);
  }

  @Override
  public void logout(final Integer userId) {
    refreshTokenRepository.deleteRefreshToken(userId);
    LoginHistory loginHistory = loginHistoryRepository.findByUserId(userId);
    loginHistory.setLogoutTime(LocalDateTime.now());
    loginHistoryRepository.saveAndFlush(loginHistory);
  }

  public LoginResponse refreshToken(final String refreshToken) {
    // Validate refresh token
    RefreshToken storedToken = refreshTokenRepository.findByToken(refreshToken);
    if (storedToken == null) {
      throw new RuntimeException("Invalid refresh token");
    }

    if (storedToken.getExpiresAt().isBefore(LocalDateTime.now())) {
      throw new RuntimeException("Refresh token expired");
    }

    // Generate new JWT token
    User user = userService.findById(storedToken.getUserId());
    if (user == null) {
      throw new UsernameNotFoundException("User not found");
    }

    String newJwtToken = jwtTokenProvider.generateToken(user, false);
    String newRefreshToken = jwtTokenProvider.generateToken(user, true);

    // Update the refresh token in the repository
    updateRefreshToken(user.getUserId(), newRefreshToken);

    return new LoginResponse(newJwtToken, newRefreshToken);
  }

  private void saveRefreshToken(Integer userId, String refreshToken) {
    RefreshToken token = new RefreshToken();
    token.setUserId(userId);
    token.setToken(refreshToken);
    token.setExpiresAt(LocalDateTime.now().plusDays(1));

    refreshTokenRepository.save(token);
  }

  private void updateRefreshToken(Integer userId, String newRefreshToken) {
    refreshTokenRepository.deleteByUserId(userId);
    saveRefreshToken(userId, newRefreshToken);
  }
}
