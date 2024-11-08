package com.mpsp.cc_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class SchoolDetails {
  private int schoolId;
  private String schoolUdiseCode;
  private Integer principalUserId;

  @JsonProperty("isVerified")
  private boolean isVerified;
}
