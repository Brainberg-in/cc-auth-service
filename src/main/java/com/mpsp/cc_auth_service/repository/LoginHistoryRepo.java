package com.mpsp.cc_auth_service.repository;

import com.mpsp.cc_auth_service.entity.LoginHistory;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LoginHistoryRepo extends JpaRepository<LoginHistory, Integer> {
  LoginHistory findByUserId(Integer userId);

  Page<LoginHistory> findAllByUserId(final Integer userId, final Pageable pageable);


}
