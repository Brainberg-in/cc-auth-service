package com.mpsp.cc_auth_service.service.impl;

import com.mpsp.cc_auth_service.dto.LoginRequest;
import com.mpsp.cc_auth_service.dto.LoginResponse;
import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.entity.LoginHistory;
import com.mpsp.cc_auth_service.entity.PasswordHistory;
import com.mpsp.cc_auth_service.entity.RefreshToken;
import com.mpsp.cc_auth_service.repository.LoginHistoryRepo;
import com.mpsp.cc_auth_service.repository.PasswordHistoryRepo;
import com.mpsp.cc_auth_service.repository.RefreshTokenRepo;
import com.mpsp.cc_auth_service.service.AuthService;
import com.mpsp.cc_auth_service.service.OtpService;
import com.mpsp.cc_auth_service.service.UserService;
import com.mpsp.cc_auth_service.utils.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private UserService userService;


    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private LoginHistoryRepo loginHistoryRepository;

    @Autowired
    private PasswordHistoryRepo passwordHistoryRepository;

    @Autowired
    private RefreshTokenRepo refreshTokenRepository;

    @Autowired
    private OtpService otpService;

    @Override
    public LoginResponse login(LoginRequest loginRequest) {
        String email = loginRequest.getEmail();
        String password = loginRequest.getPassword();

        // Validate user and password
        User user = userService.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }

        System.out.println(user.getUserId());

        PasswordHistory pw = passwordHistoryRepository.findByUserId(user.getUserId());
        System.out.println(pw.getCurrentPassword());

        if (!passwordEncoder.matches(password,
                pw.getCurrentPassword())) {
            throw new BadCredentialsException("Invalid password");
        }


        // Generate tokens
        String jwtToken = jwtTokenProvider.generateToken(user);
        String refreshToken = jwtTokenProvider.generateRefreshToken(user);
        saveRefreshToken(user.getUserId(), refreshToken);

        System.out.println("Login successful"+jwtToken);

        // Create records in the history tables
        loginHistoryRepository.save(new LoginHistory(user.getUserId(), LocalDateTime.now()));


        String otp = null;
        if (user.isMfaEnabled()) {
            otpService.sendOtp(email);// Send OTP via AWS SES/SNS
        }

        return new LoginResponse(jwtToken, refreshToken);
    }

    @Override
    public void logout(Integer userId) {
        refreshTokenRepository.deleteRefreshToken(userId);
        LoginHistory loginHistory = loginHistoryRepository.findByUserId(userId);
        loginHistory.setLogoutTime(LocalDateTime.now());
        loginHistoryRepository.saveAndFlush(loginHistory);
    }

    public LoginResponse refreshToken(String refreshToken) {
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

        String newJwtToken = jwtTokenProvider.generateToken(user);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(user);

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
