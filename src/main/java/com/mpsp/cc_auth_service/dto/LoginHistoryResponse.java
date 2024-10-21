package com.mpsp.cc_auth_service.dto;

import java.time.LocalDateTime;
import lombok.Data;

@Data
public class LoginHistoryResponse {
  private Long id;
  private Integer userId;
  private LocalDateTime lastLoginTime;
  private LocalDateTime logoutTime;
  private String ipAddress;
}
