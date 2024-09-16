package com.mpsp.cc_auth_service.controllers;


import com.mpsp.cc_auth_service.dto.UserCreateRequest;
import com.mpsp.cc_auth_service.service.UserService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/user")
@Slf4j
@Validated
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/create-user")
    public ResponseEntity<Void> createNewUser(
            @RequestBody @Valid final UserCreateRequest userCreateRequest) {
        userService.createNewUser(userCreateRequest);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }
}
