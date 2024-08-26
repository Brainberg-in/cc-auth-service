package com.mpsp.cc_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.mpsp.cc_auth_service.constants.Gender;
import com.mpsp.cc_auth_service.constants.UserStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Date;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@ToString
// User class
public class User {
  private Integer userId;
  private String fullName;
  private String mobile;
  private String email;
  private String addressLine1;
  private String addressLine2;
  private String city;
  private String pinCode;
  private String state;
  private Date dateOfBirth;
  private Gender gender;
  private UserStatus status;
  private Date createdAt;
  private Date updatedAt;
  private Long createdBy;
  private Long updatedBy;

  public User(final int userId, final String email) {
    this.userId = userId;
    this.email = email;
  }
}
