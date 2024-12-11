package com.mpsp.cc_auth_service.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Table(name = "reset_password")
@Getter
@Setter
@NoArgsConstructor
@Entity
@AllArgsConstructor
public class ResetPassword {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @CreationTimestamp
  @Column(name = "created_at", updatable = false)
  private LocalDateTime createdAt = LocalDateTime.now();

  @UpdateTimestamp
  @Column(name = "modified_at")
  private LocalDateTime modifiedAt;

  @Column(name = "user_id")
  private Integer userId;

  @Column(name = "reset_token")
  private String resetToken;

  @Column(name = "link_sent")
  private int linkSent;

  @Column(name = "link_expired")
  private boolean isLinkExpired;
}
