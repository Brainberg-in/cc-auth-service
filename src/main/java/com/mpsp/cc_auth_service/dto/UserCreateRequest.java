package com.mpsp.cc_auth_service.dto;

import com.mpsp.cc_auth_service.constants.UserRole;
import lombok.*;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class UserCreateRequest {
    private Integer userId;

    private String password;

    private UserRole role;
}
