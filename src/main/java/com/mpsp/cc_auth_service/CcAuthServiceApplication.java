package com.mpsp.cc_auth_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableAutoConfiguration
@EntityScan(basePackages = "com.mpsp.cc_auth_service.entity")
@EnableJpaRepositories(basePackages = "com.mpsp.cc_auth_service.repository")
@ComponentScan(basePackages = "com.mpsp.cc_auth_service")
public class CcAuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(CcAuthServiceApplication.class, args);
		System.out.println("Hello there");
	}

}
