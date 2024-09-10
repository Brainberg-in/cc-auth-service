package com.mpsp.cc_auth_service.repository;


import com.mpsp.cc_auth_service.entity.ResetPassword;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;


import java.util.Optional;


@Repository
public interface ResetPasswordRepo extends JpaRepository<ResetPassword, Integer> {

    @Query("SELECT rp FROM ResetPassword rp WHERE rp.resetToken = :token")
    Optional<ResetPassword> findByResetToken(String token);

    @Query("SELECT rp FROM ResetPassword rp WHERE rp.userId = :userId AND rp.isLinkSent = false")
    Optional<ResetPassword> findByUserIdAndLinkSent(Integer userId);
}
