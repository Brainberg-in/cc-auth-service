package com.mpsp.cc_auth_service.feignclients;

import com.mpsp.cc_auth_service.constants.UserStatus;
import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.dto.UsersData;
import java.util.NoSuchElementException;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

@FeignClient(name = "userServiceClient", url = "${user.service.url}")
public interface UserServiceClient {

  @GetMapping("/api/v1/users")
  default User findByEmail(@RequestParam(name = "emailId") final String emailId) {
    final UsersData users = findByEmailId(emailId);
    if (users.getMetadata().getTotalUsers() == 0) {
      throw new NoSuchElementException("User not found");
    }
    if (users.getMetadata().getTotalUsers() == 1) {
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
}
