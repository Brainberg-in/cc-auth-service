package com.mpsp.cc_auth_service.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PaginationMetadata {
  private int totalPages;
  private int totalUsers;
  private int currentPage;
  private int limit;
}
