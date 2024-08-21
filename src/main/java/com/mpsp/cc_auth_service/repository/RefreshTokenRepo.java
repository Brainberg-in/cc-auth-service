package com.mpsp.cc_auth_service.repository;

import com.mpsp.cc_auth_service.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface RefreshTokenRepo extends JpaRepository<RefreshToken, Integer> {



    public void deleteByUserId(Integer userId);

    public RefreshToken findByToken(String token);

    @Query("delete from RefreshToken rt where rt.userId = ?1")
    void deleteRefreshToken(Integer userId);
}
