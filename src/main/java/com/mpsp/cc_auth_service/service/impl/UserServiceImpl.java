package com.mpsp.cc_auth_service.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.service.UserService;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

  @Value("${user.service.url}")
  private String userServiceUrl;

  @Override
  public User findByEmail(String email) {
    try {
      final URL url = new URL(String.format("%s?emailId=%s", userServiceUrl, email));
      HttpURLConnection connection = (HttpURLConnection) url.openConnection();

      // Set up the connection
      connection.setRequestMethod("GET");
      connection.setRequestProperty("Accept", "application/json");

      System.out.println("URL: " + url);

      // Get the response code
      int responseCode = connection.getResponseCode();
      if (responseCode == HttpURLConnection.HTTP_OK) {
        // Read the response
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null) {
          response.append(line);
        }
        in.close();
        System.out.println("Response: " + response);
        // Parse the response JSON into User object
        ObjectMapper objectMapper = new ObjectMapper();
        List<User> users =
            objectMapper.readValue(response.toString(), new TypeReference<List<User>>() {});
        System.out.println("Users: " + users);
        // Return the first user if available
        if (users.isEmpty()) {
          throw new RuntimeException("No user found");
        }
        return users.get(0);
      } else {
        throw new RuntimeException("Failed : HTTP error code : " + responseCode);
      }
    } catch (Exception e) {
      throw new RuntimeException("Error occurred while fetching user", e);
    }
  }

  @Override
  public User findById(Integer id) {
    try {
      URL url = new URL(String.join("/", userServiceUrl, id.toString()));
      HttpURLConnection connection = (HttpURLConnection) url.openConnection();

      // Set up the connection
      connection.setRequestMethod("GET");
      connection.setRequestProperty("Accept", "application/json");

      // Get the response code
      int responseCode = connection.getResponseCode();
      if (responseCode == HttpURLConnection.HTTP_OK) {
        // Read the response
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null) {
          response.append(line);
        }
        in.close();

        // Parse the response JSON into User object
        ObjectMapper objectMapper = new ObjectMapper();
        User user = objectMapper.readValue(response.toString(), User.class);

        // Return the first user if available
        if (user == null) {
          throw new RuntimeException("No user found");
        }
        return user;
      } else {
        throw new RuntimeException("Failed : HTTP error code : " + responseCode);
      }
    } catch (Exception e) {
      throw new RuntimeException("Error occurred while fetching user", e);
    }
  }
}
