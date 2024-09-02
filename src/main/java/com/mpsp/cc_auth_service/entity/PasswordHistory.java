package com.mpsp.cc_auth_service.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.Date;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.cglib.core.Local;
import org.springframework.security.crypto.password.PasswordEncoder;

@Entity
@Table(name = "password_history")
@Getter
@Setter
@ToString(exclude = {"currentPassword", "ipAddress"})
@NoArgsConstructor
public class PasswordHistory {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "user_id", nullable = false)
  private Integer userId;

  @Column(name = "current_password")
  private String currentPassword;

  @Column(name = "logout_time")
  private LocalDateTime logoutTime;

  @Column(name = "ip_address")
  private String ipAddress;

  @Column(name = "created_at")
  private LocalDateTime   createdAt;

  @Column(name = "modified_at")
  private LocalDateTime modifiedAt;

  @Column(name = "user_role")
  private String userRole;

  public PasswordHistory(final Integer userId, final String currentPassword) {
    this.userId = userId;
    this.currentPassword = currentPassword;
  }

  public String toString() {
    return "PasswordHistory(id=" + this.getId() + ", userId=" + this.getUserId() + ", currentPassword=" + this.getCurrentPassword() + ", logoutTime=" + this.getLogoutTime() + ", ipAddress=" + this.getIpAddress() + ", createdAt=" + this.getCreatedAt() + ", modifiedAt=" + this.getModifiedAt() + ", userRole=" + this.getUserRole() + ")";
  }
}
