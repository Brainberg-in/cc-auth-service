package com.mpsp.cc_auth_service.service;

import com.mpsp.cc_auth_service.dto.User;

public interface UserService {
    public User findByEmail(String email);

    public User findById(Integer id);
}
