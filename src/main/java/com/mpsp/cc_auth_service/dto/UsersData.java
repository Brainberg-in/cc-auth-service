package com.mpsp.cc_auth_service.dto;

import java.util.List;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class UsersData {
  private List<User> data;
  private PaginationMetadata metadata;
}
