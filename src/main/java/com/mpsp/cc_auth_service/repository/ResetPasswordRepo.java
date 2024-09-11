package com.mpsp.cc_auth_service.repository;


import com.mpsp.cc_auth_service.entity.ResetPassword;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;


import java.util.Optional;


@Repository
public interface ResetPasswordRepo extends JpaRepository<ResetPassword, Integer> {

    Optional<ResetPassword> findByResetToken(String token);

    Optional<ResetPassword> findByUserId(Integer userId);
}
