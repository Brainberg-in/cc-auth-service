package com.mpsp.cc_auth_service.config;

import java.util.Arrays;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {

  @Value("${allowed.origins}")
  private String[] allowedOrigins;

  @Bean
  public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {

    http.cors(c -> c.configurationSource(request -> corsConfiguration()))
        .csrf(AbstractHttpConfigurer::disable) // Disable CSRF protection
        .authorizeHttpRequests(
            authorizeRequests ->
                authorizeRequests
                    .requestMatchers(
                        "/api/v1/auth/login",
                        "/api/v1/auth/refresh-token",
                        "/actuator/**",
                        "/swagger-ui/**",
                        "/swagger-config/**",
                        "/v3/api-docs/**")
                    .permitAll()
                    .requestMatchers("/api/v1/auth/**")
                    .permitAll()
                    .anyRequest()
                    .authenticated());

    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  private CorsConfiguration corsConfiguration() {
    log.info("CORS URL is: {}", Arrays.toString(allowedOrigins));
    CorsConfiguration corsConfiguration = new CorsConfiguration();
    corsConfiguration.setAllowedHeaders(List.of("*"));
    corsConfiguration.setAllowedOrigins(Arrays.asList(allowedOrigins));
    corsConfiguration.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
    corsConfiguration.setAllowCredentials(true);
    corsConfiguration.setExposedHeaders(List.of("*"));
    return corsConfiguration;
  }
}
