package com.mpsp.cc_auth_service.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.*;
import org.hibernate.annotations.ColumnDefault;

@Entity
@Table(name = "login_history")
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class LoginHistory {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "user_id", nullable = false)
  private Integer userId;

  @ColumnDefault(value = "CURRENT_TIMESTAMP")
  @Column(name = "last_login_time", columnDefinition = "DATETIME")
  private LocalDateTime lastLoginTime;

  @Column(name = "logout_time")
  private LocalDateTime logoutTime;

  @Column(name = "ip_address")
  private String ipAddress;

  public LoginHistory(final Integer userId, final LocalDateTime now, final String ipAddress) {
    this.userId = userId;
    this.lastLoginTime = now;
    this.ipAddress = ipAddress;
  }
}
