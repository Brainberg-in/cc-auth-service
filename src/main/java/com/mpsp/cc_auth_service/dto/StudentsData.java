package com.mpsp.cc_auth_service.dto;

import java.util.List;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class StudentsData {
  private List<Student> data;
  private PaginationStudentMetadata metadata;
}
    

