package com.mpsp.cc_auth_service.feignclients;

import com.mpsp.cc_auth_service.constants.UserStatus;
import com.mpsp.cc_auth_service.dto.Student;
import com.mpsp.cc_auth_service.dto.StudentsData;
import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.dto.UserDetails;
import com.mpsp.cc_auth_service.dto.UsersData;
import com.mpsp.cc_auth_service.utils.GlobalExceptionHandler.InvalidUserStatus;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "userServiceClient", url = "${user.service.url}")
public interface UserServiceClient {

  Logger logger = LoggerFactory.getLogger(UserServiceClient.class);

  @GetMapping("/api/v1/users")
  default User findByEmail(@RequestParam(name = "emailId") final String emailId) {
    final UsersData users = findByEmailId(emailId);
    if (users.getMetadata().getTotalUsers() == 0) {
      throw new NoSuchElementException("User not found");
    }
    if (users.getMetadata().getTotalUsers() == 1) {

      User user = users.getData().get(0);
      UserStatus status = user.getStatus();

      if (status == null) {
        logger.error("User {} has null status", user.getUserId());
        throw new InvalidUserStatus("Invalid user status");
      }

      switch (status) {
        case LOCKED:
          logger.info("Access attempted for locked user {}", user.getUserId());
          throw new InvalidUserStatus("User is locked. Please contact helpdesk");
        case DELETED:
          logger.info("Access attempted for deleted user {}", user.getUserId());
          throw new InvalidUserStatus("User is deleted. Please contact helpdesk");
        case ACTIVE, INACTIVE:
          return user;
        default:
          logger.warn("User {} has unexpected status: {}", user.getUserId(), status);
          throw new InvalidUserStatus("User status is not active. Please contact helpdesk");
      }
    }

    return users.getData().stream()
        .filter(user -> user.getStatus().equals(UserStatus.ACTIVE))
        .findFirst()
        .orElseThrow(() -> new NoSuchElementException("Multiple users found"));
  }

  @GetMapping(value = "/api/v1/students")
  default Student findByUniqueStudent(@RequestParam(name = "uniqueStudentId") final String uniqueStudentId) {
    final StudentsData users = findByUniqueStudentId(uniqueStudentId);
    logger.info("Response received - UsersData: {}", users);
    
    if (users.getMetadata().getTotalStudents() == 0) {
        throw new NoSuchElementException("Student not found");
    }
    if (users.getMetadata().getTotalStudents() == 1) {
        Student user = users.getData().get(0);
        UserStatus status = user.getUser().getStatus();

        if (status == null) {
            logger.error("User {} has null status", user.getUser().getUserId());
            throw new InvalidUserStatus("Invalid user status");
        }

        switch (status) {
            case LOCKED:
                logger.info("Access attempted for locked user {}", user.getUser().getUserId());
                throw new InvalidUserStatus("User is locked. Please contact helpdesk");
            case DROPPEDOUT:
                logger.info("Access attempted for dropped out user {}", user.getUser().getUserId());
                throw new InvalidUserStatus("User is droppedout. Please contact helpdesk");
            case DELETED:
                logger.info("Access attempted for deleted user {}", user.getUser().getUserId());
                throw new InvalidUserStatus("User is deleted. Please contact helpdesk");
            case ACTIVE, INACTIVE:
                return user;
            default:
                logger.warn("User {} has unexpected status: {}", user.getUser().getUserId(), status);
                throw new InvalidUserStatus("User status is not active. Please contact helpdesk");
        }
    }

    return users.getData().stream()
        .filter(user -> user.getUser().getStatus().equals(UserStatus.ACTIVE))
        .findFirst()
        .orElseThrow(() -> new NoSuchElementException("Multiple students found"));
}

  @GetMapping(value = "/api/v1/users")
  UsersData findByEmailId(@RequestParam(name = "emailId") final String emailId);

  @GetMapping(value = "/api/v1/users/{id}")
  User findById(@PathVariable(name = "id") final Integer id);

  @PutMapping(value = "/api/v1/users/{id}")
  void updateUser(@PathVariable(name = "id") final Integer id, @RequestBody final User user);

  @PutMapping(value = "/api/v1/users/{id}")
  void updateUserStatus(
      @PathVariable(name = "id") final Integer id, @RequestBody final Map<String, String> body);
  
  @PutMapping(value = "/api/v1/users/{id}")
  void updateUserVerification(
      @PathVariable(name = "id") final Integer id, @RequestBody final Map<String, Boolean> body);

  @GetMapping(value = "/api/v1/{role}/{id}")
  Optional<UserDetails> getUserDetails(
      @PathVariable(name = "id") final Integer id, @PathVariable(name = "role") final String role);

  @GetMapping(value = "/api/v1/students")
  StudentsData findByUniqueStudentId(@RequestParam(name = "uniqueStudentId") final String uniqueStudentId);
}
