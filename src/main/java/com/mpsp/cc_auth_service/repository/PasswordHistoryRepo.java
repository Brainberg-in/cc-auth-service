package com.mpsp.cc_auth_service.repository;

import com.mpsp.cc_auth_service.entity.PasswordHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface PasswordHistoryRepo extends JpaRepository<PasswordHistory, Integer> {

  @Query("SELECT ph FROM PasswordHistory ph WHERE ph.userId = :userId ORDER BY ph.logoutTime DESC")
  PasswordHistory findByUserId(int userId);
}
