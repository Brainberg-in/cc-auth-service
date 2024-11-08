package com.mpsp.cc_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
/**
 * Data Transfer Object representing user details for password reset operations. Used to transfer
 * school-specific user information between services.
 */
public class UserDetails {
  /** The unique identifier of the school associated with the user. */
  private int schoolId;
}
