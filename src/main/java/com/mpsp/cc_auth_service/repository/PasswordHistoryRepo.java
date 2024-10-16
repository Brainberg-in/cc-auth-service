package com.mpsp.cc_auth_service.repository;

import com.mpsp.cc_auth_service.entity.PasswordHistory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Map;

@Repository
public interface PasswordHistoryRepo extends JpaRepository<PasswordHistory, Integer> {

  Page<PasswordHistory> findAllByUserId(@Param("userId") final int userId, final Pageable pageable);

  @Query("SELECT new map(ph.userId as userId, ph.userRole as userRole) FROM PasswordHistory ph " +
           "WHERE ph.id IN (SELECT MAX(ph2.id) FROM PasswordHistory ph2 WHERE ph2.userId IN :userIds GROUP BY ph2.userId)")
    List<Map<String, Object>> findUserRoleByUserIds(@Param("userIds") List<Integer> userIds);
}



