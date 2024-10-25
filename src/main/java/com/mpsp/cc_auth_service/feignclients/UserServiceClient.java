package com.mpsp.cc_auth_service.feignclients;

import java.util.Map;
import java.util.NoSuchElementException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

import com.mpsp.cc_auth_service.constants.UserStatus;
import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.dto.UsersData;
import com.mpsp.cc_auth_service.utils.GlobalExceptionHandler.InvalidUserStatus;

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

      if (users.getData().get(0).getStatus() == UserStatus.LOCKED) {
        throw new InvalidUserStatus("User is locked");
      }

      if (users.getData().get(0).getStatus() == UserStatus.DELETED) {
        throw new InvalidUserStatus("User is deleted");
      }

      return users.getData().get(0);
    }

    return users.getData().stream()
        .filter(user -> user.getStatus().equals(UserStatus.ACTIVE))
        .findFirst()
        .orElseThrow(() -> new NoSuchElementException("Multiple users found"));
  }

  @GetMapping(value = "/api/v1/users")
  UsersData findByEmailId(@RequestParam(name = "emailId") final String emailId);

  @GetMapping(value = "/api/v1/users/{id}")
  User findById(@PathVariable(name = "id") final Integer id);

  @PutMapping(value = "/api/v1/users/{id}")
  void updateUser(@PathVariable(name = "id") final Integer id, @RequestBody final User user);

  @PutMapping(value = "/api/v1/users/{id}")
  void updateUserStatus(@PathVariable(name = "id") final Integer id, @RequestBody final Map<String, String> body);
}
