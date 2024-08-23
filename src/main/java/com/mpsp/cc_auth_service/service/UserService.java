package com.mpsp.cc_auth_service.service;

import com.mpsp.cc_auth_service.dto.User;

public interface UserService {
  User findByEmail(String email);

  User findById(Integer id);
}
