package com.mpsp.cc_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.mpsp.cc_auth_service.constants.Gender;
import com.mpsp.cc_auth_service.constants.UserRole;
import com.mpsp.cc_auth_service.constants.UserStatus;
import java.util.Date;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString(
    exclude = {
      "fullName",
      "mobile",
      "email",
      "addressLine1",
      "addressLine2",
      "city",
      "pincode",
      "state",
      "dateOfBirth"
    })
// User class
@JsonIgnoreProperties(ignoreUnknown = true)
public class User {
  private Integer userId;
  private String fullName;
  private String mobile;
  private String email;
  private String addressLine1;
  private String addressLine2;
  private String city;
  private String pincode;
  private String state;
  private Date dateOfBirth;
  private Gender gender;
  private UserStatus status;
  private Date createdAt;
  private Date updatedAt;
  private Long createdBy;
  private Long updatedBy;
  private UserRole role;

  @JsonProperty("isEmailVerified")
  private boolean isEmailVerified;

  @JsonProperty("isMobileVerified")
  private boolean isMobileVerified;  

  @JsonProperty("isMfaEnabled")
  private boolean isMfaEnabled;

  @JsonProperty("isFirstLogin")
  private boolean isFirstLogin;

  public User(final int userId, final String email) {
    this.userId = userId;
    this.email = email;
  }
}
