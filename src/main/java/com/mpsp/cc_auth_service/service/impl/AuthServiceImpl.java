package com.mpsp.cc_auth_service.service.impl;

import com.mpsp.cc_auth_service.constants.AppConstants;
import com.mpsp.cc_auth_service.constants.UserRole;
import com.mpsp.cc_auth_service.constants.UserStatus;
import com.mpsp.cc_auth_service.dto.ChangePasswordRequest;
import com.mpsp.cc_auth_service.dto.LoginHistoryResponse;
import com.mpsp.cc_auth_service.dto.LoginRequest;
import com.mpsp.cc_auth_service.dto.LoginResponse;
import com.mpsp.cc_auth_service.dto.ResetPasswordByAdminResponse;
import com.mpsp.cc_auth_service.dto.ResetPasswordRequest;
import com.mpsp.cc_auth_service.dto.SchoolDetails;
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
import com.mpsp.cc_auth_service.service.AuthService;
import com.mpsp.cc_auth_service.service.NotificationService;
import com.mpsp.cc_auth_service.service.OtpService;
import com.mpsp.cc_auth_service.utils.GlobalExceptionHandler;
import com.mpsp.cc_auth_service.utils.JwtTokenProvider;
import com.newrelic.api.agent.Trace;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

  @Autowired private transient ResetPasswordRepo resetPasswordRepo;

  @Autowired private transient SchoolServiceClient schoolService;

  @Autowired private transient NotificationService notificationService;

  @Autowired private transient JdbcTemplate jdbcTemplate;

  @Value("${aws.ses.sender}")
  private String senderEmail;

  @Value("${fallback.url.reset.password}")
  private String resetPasswordUrl;

  @Value("${max.login.attempts}")
  private int PASSWORD_ATTEMPTS;

  @Value("${frontend.url}")
  private String frontendUrl;

  @Override
  @Transactional
  public LoginResponse login(final LoginRequest loginRequest, final String ipAddress) {
    try {
      final String email = loginRequest.getEmail();
      final String uniqueStudentId = loginRequest.getUniqueStudentId();
      final String role = loginRequest.getRole();
      final String password = loginRequest.getPassword();

      final User user;

      if (UserRole.STUDENT.name().equals(role)) {
        if (StringUtils.isBlank(uniqueStudentId)) {
          log.error("Unique Student Id is required");
          throw new GlobalExceptionHandler.InvalidCredentialsException(
              "Unique Student Id is required");
        } else {
          user =
              userService
                  .findByUniqueStudent(uniqueStudentId)
                  .getUser(); // Get the user object from the Student object
          log.info("user: {}", user);
        }

      } else {
        // Validate user and password
        user = userService.findByEmail(email);

        log.info("User found: {}", user);
      }

      final PasswordHistory pw =
          passwordHistoryRepository
              .findAllByUserId(
                  user.getUserId(), PageRequest.of(0, 1, Sort.by("logoutTime").descending()))
              .getContent()
              .stream()
              .findFirst()
              .orElseThrow(() -> new NoSuchElementException("User not found"));

      if (!passwordEncoder.matches(password, pw.getCurrentPassword())) {
        handleFailedLoginAttempt(user, pw);
      }

      return handleSuccessfulLogin(user, pw, ipAddress);

    } catch (Exception e) {
      log.error("Unexpected error during login", e);
      throw e;
    }
  }

  private void handleFailedLoginAttempt(final User user, final PasswordHistory pw) {
    int newAttempts = pw.getFailedLoginAttempts() + 1;

    if (newAttempts == PASSWORD_ATTEMPTS) {
      user.setStatus(UserStatus.LOCKED);
      log.info("User data user{}", user);
      // userService.updateUser(user.getUserId(), user);

      final Map<String, String> userDataMap = Map.of("status", user.getStatus().toString());
      userService.updateUserStatus(user.getUserId(), userDataMap);
      passwordHistoryRepository.updateFailedLoginAttempts(pw.getUserId(), newAttempts);

    } else if (newAttempts > PASSWORD_ATTEMPTS) {
      newAttempts = 1;
      passwordHistoryRepository.updateFailedLoginAttempts(pw.getUserId(), newAttempts);

    } else {
      passwordHistoryRepository.updateFailedLoginAttempts(pw.getUserId(), newAttempts);
    }

    throw new GlobalExceptionHandler.InvalidPasswordException(
        String.format("No of attempts left %d", (PASSWORD_ATTEMPTS - newAttempts)),
        PASSWORD_ATTEMPTS - newAttempts);
  }

  private LoginResponse handleSuccessfulLogin(
      final User user, final PasswordHistory pw, final String ipAddress) {
    // Generate tokens
    final String jwtToken = jwtTokenProvider.generateToken(user, false, pw.getUserRole());
    final String refreshToken = jwtTokenProvider.generateToken(user, true, pw.getUserRole());
    saveRefreshToken(user.getUserId(), refreshToken);

    loginHistoryRepository.save(new LoginHistory(user.getUserId(), LocalDateTime.now(), ipAddress));

    final boolean isFirstLogin = user.isFirstLogin();
    // Need to remove this
    if (user.isMfaEnabled()) {
      otpService.sendOtp(user.getEmail());
    }
    // Reset failed_login_attempts on successful login
    if (pw.getFailedLoginAttempts() != 0) {
      pw.setFailedLoginAttempts(0);
      passwordHistoryRepository.updateFailedLoginAttempts(pw.getUserId(), 0);
    }

    return new LoginResponse(
        jwtToken,
        refreshToken,
        user.isMfaEnabled(),
        isFirstLogin,
        pw.getUserRole(),
        user.getStatus());
  }

  @Override
  @Transactional
  public void logout(final String token) {
    final int userId = Integer.parseInt(jwtTokenProvider.getSubject(token));
    refreshTokenRepository.deleteRefreshToken(userId);

    final Page<LoginHistory> loginHistoryPage =
        loginHistoryRepository.findAllByUserId(
            userId, PageRequest.of(0, 1, Sort.by("lastLoginTime").descending()));
    if (!loginHistoryPage.isEmpty()) {
      final LoginHistory loginHistory = loginHistoryPage.getContent().get(0);
      loginHistory.setLogoutTime(LocalDateTime.now());
      loginHistoryRepository.save(loginHistory);
    }
  }

  @Transactional
  @Override
  public LoginResponse refreshToken(final String refreshToken) {
    final RefreshToken storedToken =
        refreshTokenRepository
            .findByToken(refreshToken)
            .orElseThrow(
                () -> new GlobalExceptionHandler.RefreshTokenException("Invalid refresh token"));

    jwtTokenProvider.verifyToken(refreshToken, storedToken.getUserId().toString(), true);

    // Generate new JWT token
    log.info("User ID: {}", storedToken.getUserId());
    final User user = userService.findById(storedToken.getUserId());

    final PasswordHistory p =
        passwordHistoryRepository
            .findAllByUserId(
                user.getUserId(), PageRequest.of(0, 1, Sort.by("logoutTime").descending()))
            .getContent()
            .get(0);

    // Refresh token only gets generated when the user logs in
    // The refresh token is only used for refreshing the access token.
    final String newJwtToken = jwtTokenProvider.generateToken(user, false, p.getUserRole());
    return new LoginResponse(
        newJwtToken, refreshToken, true, false, p.getUserRole(), user.getStatus());
  }

  @Override
  @Transactional
  public void sendResetPasswordEmail(final String email) {
    final User user = userService.findByEmail(email);

    log.info("User found: {}", user);
    final String token = UUID.randomUUID().toString();

    final Optional<ResetPassword> existingTokenOpt =
        resetPasswordRepo.findByUserId(user.getUserId());
    final ResetPassword resetToken;
    if (existingTokenOpt.isPresent()) {
      if (existingTokenOpt.get().getLinkSent() >= 3
          && existingTokenOpt
              .get()
              .getModifiedAt()
              .isAfter(LocalDateTime.now().minus(Duration.ofMinutes(60)))) {
        throw new GlobalExceptionHandler.ResetPasswordException(
            "A password reset attempts limit is reached. Please try again after an hour.");
      } else {
        resetToken = existingTokenOpt.get();
        resetToken.setLinkSent(resetToken.getLinkSent() >= 3 ? 1 : resetToken.getLinkSent() + 1);
      }

    } else {
      resetToken = new ResetPassword();
      resetToken.setUserId(user.getUserId());
    }
    resetToken.setResetToken(token);
    resetToken.setLinkExpired(false);

    resetPasswordRepo.save(resetToken);

    notificationService.sendNotification(
        "email",
        "cc_reset_password",
        email,
        "",
        Map.of(
            "link",
            resetPasswordUrl + "?token=" + token,
            "username",
            user.getFullName() + "",
            "email",
            email,
            "portal",
            frontendUrl));
  }

  @Override
  public void changePassword(
      final ChangePasswordRequest changePasswordRequest, final String token) {
    final int userId = Integer.parseInt(jwtTokenProvider.getSubject(token));
    log.info("{} is trying to reset the password", userId);
    final String status = jwtTokenProvider.getClaim(token, AppConstants.USER_STATUS);
    if (StringUtils.isBlank(status) || !List.of("ACTIVE", "INACTIVE").contains(status)) {
      log.error("User {} is not active, Status is {}", userId, status);
      throw new GlobalExceptionHandler.InvalidCredentialsException("UnAuthorized Access");
    }

    if ("ACTIVE".equals(status)
        && StringUtils.isBlank(changePasswordRequest.getCurrentPassword())) {
      throw new GlobalExceptionHandler.GenericException("Current password is required");
    }

    final PasswordHistory passwordHistory =
        passwordHistoryRepository
            .findAllByUserId(userId, PageRequest.of(0, 1, Sort.by("logoutTime").descending()))
            .getContent()
            .get(0);

    if ("ACTIVE".equals(status)
        && StringUtils.isNotBlank(changePasswordRequest.getCurrentPassword())) {
      if (passwordEncoder.matches(
          changePasswordRequest.getPassword(), passwordHistory.getCurrentPassword())) {
        throw new GlobalExceptionHandler.SamePasswordException(
            "New password cannot be the same as the current password");
      } else if (!passwordEncoder.matches(
          changePasswordRequest.getCurrentPassword(), passwordHistory.getCurrentPassword())) {
        throw new GlobalExceptionHandler.InvalidCredentialsException("Invalid password");
      }
    }
    if (passwordHistory != null) {
      passwordHistory.setCurrentPassword(
          passwordEncoder.encode(changePasswordRequest.getPassword()));
      passwordHistory.setUserId(userId);
      passwordHistoryRepository.save(passwordHistory);
    }
    final User user = userService.findById(userId);
    if ("INACTIVE".equals(status) && user.isFirstLogin()) {
      log.info("User status is INACTIVE. Hence making first login false since password is reset");
      user.setFirstLogin(false);
      userService.updateUser(user.getUserId(), user);
    }

    if ("INACTIVE".equals(status)
        && user.getRole() != null
        && user.getRole().equals(UserRole.STUDENT)) {
      userService.updateUserStatus(userId, Map.of("status", UserStatus.ACTIVE.toString()));
    }
    if (user.getEmail() != null && !user.getEmail().isEmpty()) {
      notificationService.sendNotification(
          "email",
          "password_update",
          user.getEmail() + "",
          "",
          Map.of(
              "email",
              user.getEmail() + "",
              "username",
              user.getFullName() + "",
              "portal",
              frontendUrl));
    }
  }

  @Override
  @Transactional
  @Trace(dispatcher = true)
  @RabbitListener(queues = "${rabbitmq.queue.name}")
  public void createNewUser(final UserCreateRequest userCreateRequest) {
    log.info("User created: {}", userCreateRequest);
    final String sql =
        "INSERT INTO password_history (user_id, current_password, user_role, created_at,"
            + " modified_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)";
    jdbcTemplate.update(
        sql,
        userCreateRequest.getUserId(),
        passwordEncoder.encode(userCreateRequest.getPassword()),
        userCreateRequest.getRole().toString());
  }

  @Transactional
  @Override
  public void resetPasswordSelf(final ResetPasswordRequest resetPasswordRequest) {
    final ResetPassword resetToken =
        resetPasswordRepo
            .findByResetToken(resetPasswordRequest.getResetToken())
            .orElseThrow(
                () ->
                    new GlobalExceptionHandler.GenericException(
                        "Link is Invalid/Expired. Please request a new link"));

    if (resetToken.isLinkExpired()) {
      throw new GlobalExceptionHandler.GenericException(
          "Link is Invalid/Expired. Please request a new link");
    }

    final PasswordHistory passwordHistory =
        passwordHistoryRepository
            .findAllByUserId(
                resetToken.getUserId(), PageRequest.of(0, 1, Sort.by("logoutTime").descending()))
            .getContent()
            .get(0);

    if (passwordEncoder.matches(
        resetPasswordRequest.getPassword(), passwordHistory.getCurrentPassword())) {
      throw new GlobalExceptionHandler.SamePasswordException(
          "New password cannot be the same as the current password");
    }

    passwordHistory.setCurrentPassword(passwordEncoder.encode(resetPasswordRequest.getPassword()));
    passwordHistory.setModifiedAt(LocalDateTime.now());
    passwordHistoryRepository.saveAndFlush(passwordHistory);

    resetToken.setLinkExpired(true);
    resetToken.setLinkSent(0);
    resetPasswordRepo.saveAndFlush(resetToken);
  }

  @Override
  @Transactional
  public ResetPasswordByAdminResponse resetPasswordByAdmin(
      final ResetPasswordRequest resetPasswordRequest, final String token) {
    final int userId = Integer.parseInt(jwtTokenProvider.getSubject(token));
    final UserRole userRole =
        UserRole.valueOf(jwtTokenProvider.getClaim(token, AppConstants.USER_ROLE));

    if (!List.of(UserRole.PRINCIPAL, UserRole.HELPDESKADMIN, UserRole.HELPDESKUSER)
        .contains(userRole)) {
      log.error("{} is not allowed to reset password", userRole);
      throw new GlobalExceptionHandler.InvalidUserStatus("Forbidden");
    }
    final Map<Integer, String> failureReasons = new HashMap<>();
    final List<PasswordHistory> toBeSavedPasswordHistoryList = new ArrayList<>();
    for (UserIdAndRole userIdAndRole : resetPasswordRequest.getBehalfOf()) {
      if (userIdAndRole.getUserRole() == null) {
        failureReasons.put(userIdAndRole.getUserId(), "User role is required");
        continue;
      }
      final UserDetails behalfUserDetails =
          userService
              .getUserDetails(
                  userIdAndRole.getUserId(),
                  String.join("", userIdAndRole.getUserRole().toLowerCase(), "s"))
              .orElseThrow();

      if (!List.of(UserStatus.ACTIVE, UserStatus.INACTIVE)
          .contains(behalfUserDetails.getUser().getStatus())) {
        failureReasons.put(
            userIdAndRole.getUserId(),
            String.format(
                "Failed to reset password because user status is not %s",
                behalfUserDetails.getUser().getStatus()));
        continue;
      }
      if (UserRole.PRINCIPAL.equals(userRole)) {
        final SchoolDetails schoolDetails =
            schoolService.getSchoolDetails(behalfUserDetails.getSchoolId(), true);
        if (userId != schoolDetails.getPrincipalUserId()) {
          failureReasons.put(
              userIdAndRole.getUserId(), "User does not belong to the principal school");
          continue;
        }
      }
      final List<PasswordHistory> passwordHistoryList =
          passwordHistoryRepository
              .findAllByUserId(
                  behalfUserDetails.getUser().getUserId(),
                  PageRequest.of(0, 1, Sort.by("logoutTime").descending()))
              .getContent();
      if (passwordHistoryList.isEmpty()) {
        failureReasons.put(
            userIdAndRole.getUserId(), "Cannot find any password history for the user");
      } else {
        final PasswordHistory passwordHistory = passwordHistoryList.get(0);

        final String generatedPassword =
            String.join(
                "@",
                behalfUserDetails
                    .getUser()
                    .getFullName()
                    .replaceAll(" ", "")
                    .toUpperCase()
                    .substring(0, 4),
                "123");

        passwordHistory.setCurrentPassword(passwordEncoder.encode(generatedPassword));
        passwordHistory.setModifiedAt(LocalDateTime.now());
        toBeSavedPasswordHistoryList.add(passwordHistory);
        if (StringUtils.isNotBlank(behalfUserDetails.getUser().getEmail())) {
          notificationService.sendNotification(
              "email",
              "reset_password_mail",
              behalfUserDetails.getUser().getEmail() + "",
              "",
              Map.of(
                  "email",
                  behalfUserDetails.getUser().getEmail(),
                  "password",
                  generatedPassword,
                  "portal",
                  frontendUrl));
        }
      }
    }
    if (!toBeSavedPasswordHistoryList.isEmpty()) {
      passwordHistoryRepository.saveAll(toBeSavedPasswordHistoryList);
      return new ResetPasswordByAdminResponse(failureReasons, "Password reset successfully.");
    }

    if (resetPasswordRequest.getBehalfOf().size() == 1) {
      throw new GlobalExceptionHandler.ResetPasswordException(
          failureReasons.get(resetPasswordRequest.getBehalfOf().get(0).getUserId()));
    } else {
      throw new GlobalExceptionHandler.ResetPasswordException(
          "There is no history of password for the given users. Hence cannot reset the password");
    }
  }

  @Transactional
  private void saveRefreshToken(final Integer userId, final String refreshToken) {
    final RefreshToken token =
        refreshTokenRepository.findByToken(refreshToken).orElse(new RefreshToken());

    token.setUserId(userId);
    token.setToken(refreshToken);
    token.setExpiresAt(LocalDateTime.now().plusDays(1));

    refreshTokenRepository.save(token);
  }

  @Transactional(readOnly = true)
  @Override
  public Map<Integer, String> getUserRoles(final List<Integer> userIds) {
    final List<Map<String, Object>> latestUserTypes =
        passwordHistoryRepository.findUserRoleByUserIds(userIds);

    final Map<Integer, String> userRoles =
        latestUserTypes.stream()
            .collect(
                Collectors.toMap(
                    entry -> ((Number) entry.get("userId")).intValue(),
                    entry -> (String) entry.get("userRole")));

    // Ensure all requested userIds are in the map, even if they don't have a role
    for (Integer userId : userIds) {
      userRoles.putIfAbsent(userId, "UNKNOWN");
    }

    return userRoles;
  }

  @Override
  @Transactional(readOnly = true)
  public List<LoginHistoryResponse> getLoginHistory(final Integer userId) {
    log.info("Getting login history for userId: {}", userId);
    // only return the last 10 login details.
    final Page<LoginHistory> loginHistoryPage =
        loginHistoryRepository.findAllByUserId(
            userId, PageRequest.of(0, 10, Sort.by("lastLoginTime").descending()));
    final List<LoginHistory> loginHistoryList = loginHistoryPage.getContent();
    return loginHistoryList.stream()
        .map(this::convertToLoginHistoryResponse)
        .collect(Collectors.toList());
  }

  private LoginHistoryResponse convertToLoginHistoryResponse(final LoginHistory loginHistory) {
    LoginHistoryResponse response = new LoginHistoryResponse();
    response.setId(loginHistory.getId());
    response.setUserId(loginHistory.getUserId());
    response.setLastLoginTime(loginHistory.getLastLoginTime());
    response.setLogoutTime(loginHistory.getLogoutTime());
    response.setIpAddress(loginHistory.getIpAddress());
    return response;
  }
}
