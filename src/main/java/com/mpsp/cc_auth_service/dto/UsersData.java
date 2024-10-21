package com.mpsp.cc_auth_service.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@Getter
@AllArgsConstructor
@ToString
public class UsersData {
  private List<User> data;
  private PaginationMetadata metadata;
}
