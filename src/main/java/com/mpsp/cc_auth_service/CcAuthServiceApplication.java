package com.mpsp.cc_auth_service;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpHeaders;

@SecurityScheme(
    type = SecuritySchemeType.APIKEY,
    name = HttpHeaders.AUTHORIZATION,
    in = SecuritySchemeIn.HEADER)
@OpenAPIDefinition(
    security = {@SecurityRequirement(name = HttpHeaders.AUTHORIZATION)},
    info =
        @Info(title = "cc-auth-service", description = "Swagger documentation for cc-auth-service"))
@SpringBootApplication
public class CcAuthServiceApplication {

  public static void main(String[] args) {
    SpringApplication.run(CcAuthServiceApplication.class, args);
  }
}
