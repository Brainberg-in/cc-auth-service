package com.mpsp.cc_auth_service.repository;

import java.util.List;
import java.util.Map;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.mpsp.cc_auth_service.entity.PasswordHistory;

@Repository
public interface PasswordHistoryRepo extends JpaRepository<PasswordHistory, Integer> {

  Page<PasswordHistory> findAllByUserId(@Param("userId") final int userId, final Pageable pageable);

  @Query("SELECT new map(ph.userId as userId, ph.userRole as userRole) FROM PasswordHistory ph " +
      "WHERE ph.id IN (SELECT MAX(ph2.id) FROM PasswordHistory ph2 WHERE ph2.userId IN :userIds GROUP BY ph2.userId)")
  List<Map<String, Object>> findUserRoleByUserIds(@Param("userIds") List<Integer> userIds);

  @Modifying
  @Query(value = "UPDATE password_history ph SET ph.failed_login_attempts = 0 WHERE ph.user_id = :userId LIMIT 1", nativeQuery = true)
  void resetFailedLoginAttempts(@Param("userId") int userId);

  @Modifying
  @Query(value = "UPDATE password_history ph SET ph.failed_login_attempts = :attempts WHERE ph.user_id = :userId LIMIT 1", nativeQuery = true)
  void incrementFailedLoginAttemptsInDb(@Param("userId") int userId, @Param("attempts") int attempts);
}
