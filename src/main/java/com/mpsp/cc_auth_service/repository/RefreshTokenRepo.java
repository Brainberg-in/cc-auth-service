package com.mpsp.cc_auth_service.repository;

import com.mpsp.cc_auth_service.entity.RefreshToken;
import jakarta.transaction.Transactional;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepo extends JpaRepository<RefreshToken, Integer> {

  void deleteByUserId(final Integer userId);

  Optional<RefreshToken> findByToken(final String token);

  @Query("delete from RefreshToken rt where rt.userId = ?1")
  @Transactional
  @Modifying
  void deleteRefreshToken(final Integer userId);

  RefreshToken findByUserId(final Integer userId);

  @Query("update RefreshToken rt set rt.token = ?2 where rt.userId = ?1")
  @Transactional
  @Modifying
  void updateRefreshToken(final Integer userId, final String newRefreshToken);
}
