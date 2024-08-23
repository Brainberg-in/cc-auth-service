package com.mpsp.cc_auth_service.serviceTests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.service.impl.UserServiceImpl;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.test.util.ReflectionTestUtils;

public class UserServiceImplTest {

  @Mock private ObjectMapper objectMapper;

  @InjectMocks private UserServiceImpl userService;

  @Mock private HttpURLConnection connection;

  @BeforeEach
  public void setUp() throws Exception {
    MockitoAnnotations.openMocks(this);
    ReflectionTestUtils.setField(userService, "userServiceUrl", "http://mockurl.com");
  }

  @Test
  public void testFindByEmail_Success() throws Exception {
    // Mock URL and connection
    URL url = new URL("http://mockurl.com?emailId=test@example.com");
    when(connection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
    when(connection.getInputStream())
        .thenReturn(
            (InputStream)
                new BufferedReader(
                        new InputStreamReader(
                            new ByteArrayInputStream(
                                "[{\"id\":1,\"email\":\"test@example.com\"}]".getBytes())))
                    .lines());

    // Mock ObjectMapper
    List<User> users = Collections.singletonList(new User(1, "test@example.com"));
    when(objectMapper.readValue(any(String.class), any(TypeReference.class))).thenReturn(users);

    // Call the method
    User result = userService.findByEmail("test@example.com");

    // Verify
    assertEquals(1, result.getUserId());
    assertEquals("test@example.com", result.getEmail());
  }

  @Test
  public void testFindByEmail_NoUserFound() throws Exception {
    // Mock URL and connection
    URL url = new URL("http://mockurl.com?emailId=test@example.com");
    when(connection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
    when(connection.getInputStream())
        .thenReturn(
            (InputStream)
                new BufferedReader(new InputStreamReader(new ByteArrayInputStream("[]".getBytes())))
                    .lines());

    // Mock ObjectMapper
    when(objectMapper.readValue(any(String.class), any(TypeReference.class)))
        .thenReturn(Collections.emptyList());

    // Call the method and verify exception
    assertThrows(RuntimeException.class, () -> userService.findByEmail("test@example.com"));
  }

  @Test
  public void testFindById_Success() throws Exception {
    // Mock URL and connection
    URL url = new URL("http://mockurl.com/1");
    when(connection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
    when(connection.getInputStream())
        .thenReturn(
            (InputStream)
                new BufferedReader(
                        new InputStreamReader(
                            new ByteArrayInputStream(
                                "{\"id\":1,\"email\":\"test@example.com\"}".getBytes())))
                    .lines());

    // Mock ObjectMapper
    User user = new User(1, "test@example.com");
    when(objectMapper.readValue(any(String.class), eq(User.class))).thenReturn(user);

    // Call the method
    User result = userService.findById(1);

    // Verify
    assertEquals(1, result.getUserId());
    assertEquals("test@example.com", result.getEmail());
  }

  @Test
  public void testFindById_NoUserFound() throws Exception {
    // Mock URL and connection
    URL url = new URL("http://mockurl.com/1");
    when(connection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
    when(connection.getInputStream())
        .thenReturn(
            (InputStream)
                new BufferedReader(new InputStreamReader(new ByteArrayInputStream("{}".getBytes())))
                    .lines());

    // Mock ObjectMapper
    when(objectMapper.readValue(any(String.class), eq(User.class))).thenReturn(null);

    // Call the method and verify exception
    assertThrows(RuntimeException.class, () -> userService.findById(1));
  }
}
