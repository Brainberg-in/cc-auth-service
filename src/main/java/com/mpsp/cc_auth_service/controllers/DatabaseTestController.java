package com.mpsp.cc_auth_service.controllers;

import java.sql.Connection;
import java.sql.SQLException;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class DatabaseTestController {

  @Autowired private DataSource dataSource;

  @GetMapping("/connection")
  public String testConnection() {
    try (Connection connection = dataSource.getConnection()) {
      if (connection != null) {
        return "Database connection successful!";
      } else {
        return "Failed to connect to the database.";
      }
    } catch (SQLException e) {
      e.printStackTrace();
      return "Error connecting to the database: " + e.getMessage();
    }
  }
}
