package com.mpsp.cc_auth_service.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {

  @Autowired private transient CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

  @Autowired private transient JwtAuthorizationFilter jwtAuthorizationFilter;

  @Bean
  public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {

    http.sessionManagement(
            (session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .csrf(AbstractHttpConfigurer::disable) // Disable CSRF protection
        .authorizeHttpRequests(
            authorizeRequests ->
                authorizeRequests
                    .requestMatchers(
                        "/api/v1/auth/login",
                        "/api/v1/auth/refresh-token",
                        "/api/v1/auth/create-user",
                        "/actuator/health",
                        "/swagger-ui/**",
                        "/swagger-config/**",
                        "/api/v1/auth/forgot-password",
                        "/api/v1/auth/reset-password/self",
                        "/api/v1/auth/user-roles",
                        "/api/v1/auth/login-history/**",
                        "/v3/api-docs/**")
                    .permitAll()
                    .requestMatchers("/api/v1/auth/**")
                    .authenticated()
                    .anyRequest()
                    .denyAll())
        .addFilterBefore(jwtAuthorizationFilter, BasicAuthenticationFilter.class)
        .exceptionHandling(
            (exceptionHandling) ->
                exceptionHandling.authenticationEntryPoint(customAuthenticationEntryPoint));
    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
