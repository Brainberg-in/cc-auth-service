package com.mpsp.cc_auth_service.service;

import com.mpsp.cc_auth_service.dto.UserCreateRequest;

public interface UserService {

    void createNewUser(UserCreateRequest userCreateRequest);
}
