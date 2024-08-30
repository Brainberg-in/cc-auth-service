package com.mpsp.cc_auth_service.repository;

import com.mpsp.cc_auth_service.entity.RefreshToken;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface RefreshTokenRepo extends JpaRepository<RefreshToken, Integer> {

  void deleteByUserId(Integer userId);

  RefreshToken findByToken(String token);

  @Query("delete from RefreshToken rt where rt.userId = ?1")
  @Transactional
  @Modifying
  void deleteRefreshToken(Integer userId);

  RefreshToken findByUserId(Integer userId);

  @Query("update RefreshToken rt set rt.token = ?2 where rt.userId = ?1")
  @Transactional
  @Modifying
  void updateRefreshToken(Integer userId, String newRefreshToken);
}
