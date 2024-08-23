package com.mpsp.cc_auth_service.repository;

import com.mpsp.cc_auth_service.entity.LoginHistory;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LoginHistoryRepo extends JpaRepository<LoginHistory, Integer> {
  LoginHistory findByUserId(Integer userId);
}
