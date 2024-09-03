package com.mpsp.cc_auth_service.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mpsp.cc_auth_service.constants.AppConstants;
import com.mpsp.cc_auth_service.error.ErrorResponse;
import com.mpsp.cc_auth_service.utils.GeneratorUtils;
import com.mpsp.cc_auth_service.utils.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {
  @Autowired private transient JwtTokenProvider tokenProvider;

  @Value("${skip.authorization.paths}")
  private String[] skipTokenCheckPaths;

  @Value("${skip.authorization.urls}")
  private String[] skipAuthorizationUrls;

  @Override
  protected void doFilterInternal(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final FilterChain filterChain)
      throws ServletException, IOException {
    String token = request.getHeader(HttpHeaders.AUTHORIZATION);
    // checking if token is present and is of bearer type. Also checking if the request is for
    // refreshing token
    if (GeneratorUtils.checkIfUrlEndsWith(request.getRequestURI(), skipAuthorizationUrls)
        || GeneratorUtils.checkIfUrlsContainUri(request.getRequestURI(), skipTokenCheckPaths)) {
      log.info("Skipping Authorization check for {}", request.getRequestURI());
      filterChain.doFilter(request, response);
      return;
    }
    if (StringUtils.isBlank(token) || !token.startsWith(AppConstants.BEARER)) {
      log.error(
          "Authorization token is blank or of not of bearer type on {}", request.getRequestURI());

      response
          .getWriter()
          .write(
              new ObjectMapper()
                  .writeValueAsString(new ErrorResponse("Unauthorized", "Token Not Found")));
      response.setStatus(HttpStatus.UNAUTHORIZED.value());
      response.setContentType(MediaType.APPLICATION_JSON_VALUE);
      return;
    }
    token = token.substring(AppConstants.BEARER.length());
    final String userId = tokenProvider.getSubject(token);
    if (tokenProvider.verifyToken(token, userId, false)) {
      UsernamePasswordAuthenticationToken authentication =
          new UsernamePasswordAuthenticationToken(tokenProvider.getSubject(token), null, null);
      SecurityContextHolder.getContext().setAuthentication(authentication);
      filterChain.doFilter(request, response);
    } else {
      log.error("Cannot Authorize {} to access {}", userId, request.getRequestURI());
      response
          .getWriter()
          .write(
              new ObjectMapper()
                  .writeValueAsString(new ErrorResponse("Unauthorized", "Invalid Token")));
      response.setStatus(HttpStatus.UNAUTHORIZED.value());
      response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    }
  }
}
