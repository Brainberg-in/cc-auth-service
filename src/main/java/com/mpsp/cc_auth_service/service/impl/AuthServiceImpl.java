package com.mpsp.cc_auth_service.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Date;
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

      final Map<String, Object> userDataMap = Map.of("status", user.getStatus().toString());
      userService.updateUser(user.getUserId(), user.getUserId(), userDataMap);
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
    final String jwtToken =
        jwtTokenProvider.generateToken(user, false, pw.getUserRole(), !user.isMfaEnabled());
    String refreshToken = null;
    if (!user.isMfaEnabled()) {
      refreshToken = jwtTokenProvider.generateToken(user, true, pw.getUserRole(), true);
      saveRefreshToken(user.getUserId(), refreshToken);
    }

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

    jwtTokenProvider.verifyToken(refreshToken, storedToken.getUserId().toString(), true, true);

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
    final String newJwtToken = jwtTokenProvider.generateToken(user, false, p.getUserRole(), true);
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

    if (UserStatus.ACTIVE.name().equals(status)
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
    if (UserStatus.INACTIVE.name().equals(status) && user.isFirstLogin()) {
      log.info("User status is INACTIVE. Hence making first login false since password is reset");
      user.setFirstLogin(false);
      userService.updateUser(user.getUserId(), user.getUserId(), user);
    }

    if (UserStatus.INACTIVE.name().equals(status)
        && user.getRole() != null
        && user.getRole().equals(UserRole.STUDENT)) {
      userService.updateUser(userId, userId, Map.of("status", UserStatus.ACTIVE.toString()));
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

  @Transactional
  @Trace(dispatcher = true)
  @RabbitListener(queues = "${rabbitmq.queue.name}")
  public void createNewUser(final String userCreateRequest) {
    try {
      final UserCreateRequest userCreateRequestObj =
          new ObjectMapper().readValue(userCreateRequest, UserCreateRequest.class);
      createNewUser(userCreateRequestObj);
    } catch (JsonMappingException e) {
      log.error("Error while parsing the request", e);
      e.printStackTrace();
    } catch (JsonProcessingException e) {
      log.error("Error while processing the request", e);
    }
  }

  public void createNewUser(final UserCreateRequest userCreateRequest) {
    log.info("User creation Request: {}", userCreateRequest);
    if (StringUtils.isBlank(userCreateRequest.getPassword())) {
      log.warn("Password is blank. Skipping creating user");
    } else {
      final PasswordHistory passwordHistory =
          new PasswordHistory(
              userCreateRequest.getUserId(),
              passwordEncoder.encode(userCreateRequest.getPassword()),
              userCreateRequest.getRole().toString());

      passwordHistoryRepository.save(passwordHistory);
    }
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

      if (!List.of(UserStatus.ACTIVE, UserStatus.INACTIVE, UserStatus.LOCKED)
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
            createDefaultPassword(
                behalfUserDetails.getUser().getFullName(),
                behalfUserDetails.getUser().getMobile(),
                behalfUserDetails.getUser().getDateOfBirth(),
                userIdAndRole.getUserRole(),
                schoolService
                    .getSchoolDetails(behalfUserDetails.getSchoolId(), true)
                    .getSchoolUdiseCode());

        passwordHistory.setCurrentPassword(passwordEncoder.encode(generatedPassword));
        passwordHistory.setModifiedAt(LocalDateTime.now());
        userService.updateUser(
            behalfUserDetails.getUser().getUserId(),
            userId,
            Map.of("status", UserStatus.INACTIVE.toString()));
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
  public void saveRefreshToken(final Integer userId, final String refreshToken) {
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

  private String createDefaultPassword(
      final String fullName,
      final String mobile,
      final Date dateOfBirth,
      final String role,
      final String schoolUdiseCode) {
    String name = (String) fullName.replaceAll(" ", "").toUpperCase().substring(0, 4);
    String mobileUpdated = (String) mobile;
    mobileUpdated =
        (mobileUpdated != null && mobileUpdated.length() >= 4)
            ? mobileUpdated.substring(mobileUpdated.length() - 4)
            : "";
    String udise =
        (schoolUdiseCode != null && schoolUdiseCode.length() >= 4)
            ? schoolUdiseCode.substring(schoolUdiseCode.length() - 4)
            : schoolUdiseCode != null ? schoolUdiseCode : "";

    String modifiedDob = "";
    if (dateOfBirth != null) {
      String[] dob = {};
      SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
      dob = sdf.format((Date) dateOfBirth).split("-");
      String year = dob[0].substring(dob[0].length() - 2);
      String month = dob[1];
      modifiedDob = month + year;
    }

    if (role != null && role.equals("STUDENT")) {
      return name + modifiedDob + udise;
    } else if (role != null
        && (role.equals("PRINCIPAL") || role.equals("TEACHER") || role.equals("POC"))) {
      return name + "@" + mobileUpdated + "@" + udise;
    }

    return name + "@123";
  }
}
