package com.mpsp.cc_auth_service.repository;

import com.mpsp.cc_auth_service.entity.PasswordHistory;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PasswordHistoryRepo extends JpaRepository<PasswordHistory, Integer> {

  PasswordHistory findByUserId(int userId);
}
