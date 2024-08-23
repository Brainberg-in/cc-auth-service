package com.mpsp.cc_auth_service.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Entity
@Table(name = "password_history")
@Getter
@Setter
@ToString
public class PasswordHistory {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "user_id", nullable = false)
  private Integer userId;

  @Column(name = "current_password", length = 255)
  private String currentPassword;

  @Column(name = "logout_time")
  private LocalDateTime logoutTime;

  @Column(name = "ip_address", length = 255)
  private String ipAddress;

  public String getCurrentPassword() {
    return currentPassword;
  }

  public PasswordHistory() {}

  public PasswordHistory(Integer userId, String currentPassword) {
    this.userId = userId;
    this.currentPassword = currentPassword;
    // this.ipAddress = o.toString();
  }

  public void setUserId(Integer userId) {
    this.userId = userId;
  }

  public Integer getUserId() {
    return userId;
  }

  public void setCurrentPassword(String currentPassword) {
    this.currentPassword = currentPassword;
  }

  public void setLogoutTime(LocalDateTime logoutTime) {
    this.logoutTime = logoutTime;
  }
}
