package com.mpsp.cc_auth_service.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PaginationStudentMetadata {
  private int totalPages;
  private int totalStudents;
  private int currentPage;
  private int limit;
}
