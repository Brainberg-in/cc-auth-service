package com.mpsp.cc_auth_service.feignclients;

import com.mpsp.cc_auth_service.dto.User;
import java.util.List;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "userServiceClient", url = "${user.service.url}")
public interface UserServiceClient {

  @GetMapping("/")
  default User findByEmail(@RequestParam(name = "emailId") final String emailId) {
    List<User> items = findByEmailId(emailId);
    if (items.isEmpty() || items.get(0) == null) {
      throw new RuntimeException("No user found");
    }
    return items.get(0);
  }

  @GetMapping(value = "/")
  List<User> findByEmailId(@RequestParam(name = "emailId") final String emailId);

  @GetMapping(value = "/:id")
  User findById(@PathVariable(name = "id") final Integer id);
}
