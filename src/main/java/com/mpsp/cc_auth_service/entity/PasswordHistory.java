package com.mpsp.cc_auth_service.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

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
  private LocalDateTime createdAt;

  @Column(name = "modified_at")
  private LocalDateTime modifiedAt;

  @Column(name = "user_role")
  private String userRole;

  public PasswordHistory(final Integer userId, final String currentPassword) {
    this.userId = userId;
    this.currentPassword = currentPassword;
  }
}
