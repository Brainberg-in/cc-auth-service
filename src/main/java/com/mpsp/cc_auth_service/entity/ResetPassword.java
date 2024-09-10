package com.mpsp.cc_auth_service.entity;


import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;


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

    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "modified_at")
    private LocalDateTime modifiedAt;

    @Column(name = "user_id")
    private Integer userId;

    @Column(name = "reset_token")
    private String resetToken;

    @Column(name = "link_sent")
    private boolean isLinkSent;

    @Column(name = "link_expired")
    private boolean isLinkExpired;
}
