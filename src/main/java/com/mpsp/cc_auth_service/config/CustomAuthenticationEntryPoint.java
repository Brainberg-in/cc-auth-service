package com.mpsp.cc_auth_service.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mpsp.cc_auth_service.error.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
  @Override
  public void commence(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final AuthenticationException authException)
      throws IOException {
    log.error("Unauthorized error: {}", request.getRequestURI(), authException);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response
        .getWriter()
        .write(
            new ObjectMapper()
                .writeValueAsString(
                    new ErrorResponse(
                        HttpStatus.UNAUTHORIZED.getReasonPhrase(), "Token Not Found")));
    response.setStatus(HttpStatus.FORBIDDEN.value());
  }
}
