package com.mpsp.cc_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString(
    exclude = {
      "schoolId",
      "counselorTeacherId",
      "grade",
      "section",
      "disability",
      "assessmentStatus",
      "counselingStatus",
      "user"
      
    })
// User class
@JsonIgnoreProperties(ignoreUnknown = true)
public class Student {
  private User user;
  private int studentId;
  private int schoolId;
  private String uniqueStudentId;
  private int counselorTeacherId;
  private String grade;
  private String section;
  private String disability;
  private String assessmentStatus;
  private String counselingStatus;
  
  
  public Student(final int studentId, final String uniqueStudentId) {
    this.studentId = studentId;
    this.uniqueStudentId = uniqueStudentId;
  }
}
