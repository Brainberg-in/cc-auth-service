package com.mpsp.cc_auth_service.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Setter
@Getter
@Entity
@Table(name = "otp_gen")
@ToString(exclude = {"otp"})
public class OtpGen {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Integer id;

  @Column(name = "userId", nullable = false)
  private Integer userId;

  @CreationTimestamp
  @Column(
      name = "createdAt",
      columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
      updatable = false)
  private LocalDateTime createdAt;

  @Column(name = "modifiedAt")
  @UpdateTimestamp
  private LocalDateTime modifiedAt;

  @Column(name = "otp")
  private String otp;
}
