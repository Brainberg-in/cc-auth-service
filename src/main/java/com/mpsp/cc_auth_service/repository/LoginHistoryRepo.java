package com.mpsp.cc_auth_service.repository;

import com.mpsp.cc_auth_service.entity.LoginHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface LoginHistoryRepo extends JpaRepository<LoginHistory, Integer> {
  LoginHistory findByUserId(Integer userId);

  @Query("select lh from LoginHistory lh where lh.userId = ?1 order by lh.lastLoginTime desc limit 1")
  LoginHistory findByUserLatestLoginTime(Integer userId);


}
