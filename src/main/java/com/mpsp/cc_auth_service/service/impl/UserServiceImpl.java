package com.mpsp.cc_auth_service.service.impl;


import com.mpsp.cc_auth_service.dto.UserCreateRequest;
import com.mpsp.cc_auth_service.entity.PasswordHistory;
import com.mpsp.cc_auth_service.repository.PasswordHistoryRepo;
import com.mpsp.cc_auth_service.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@Slf4j
public class UserServiceImpl implements UserService {

    @Autowired
    private transient PasswordEncoder passwordEncoder;

    @Autowired private transient PasswordHistoryRepo passwordHistoryRepository;


    @Override
    public void createNewUser(UserCreateRequest userCreateRequest) {
        Optional<PasswordHistory> existingHistoryOpt = passwordHistoryRepository.findByUserId(userCreateRequest.getUserId());

        PasswordHistory passwordHistory;
        if (existingHistoryOpt.isPresent()) {
            passwordHistory = existingHistoryOpt.get();
            String existingRoles = passwordHistory.getUserRole();
            if (!existingRoles.contains(userCreateRequest.getRole().toString())) {
                passwordHistory.setUserRole(existingRoles + "," + userCreateRequest.getRole().toString());
            }
        } else {
            passwordHistory = new PasswordHistory();
            passwordHistory.setUserId(userCreateRequest.getUserId());
            passwordHistory.setCurrentPassword(passwordEncoder.encode(userCreateRequest.getPassword()));
            passwordHistory.setUserRole(userCreateRequest.getRole().toString());
            passwordHistory.setCreatedAt(LocalDateTime.now());
        }
        passwordHistory.setModifiedAt(LocalDateTime.now());
        passwordHistoryRepository.saveAndFlush(passwordHistory);
    }

}
