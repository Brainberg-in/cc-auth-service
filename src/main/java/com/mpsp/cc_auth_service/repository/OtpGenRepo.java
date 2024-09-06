package com.mpsp.cc_auth_service.repository;

import com.mpsp.cc_auth_service.entity.OtpGen;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface OtpGenRepo extends JpaRepository<OtpGen, Long> {
  Optional<OtpGen> findByUserId(Integer userId);

    // @Modifying
    // @Query("UPDATE OtpGen o SET o.isActive = false WHERE o.userId = :userId")
    // void deactivateAllUserOtps(@Param("userId") int userId);

    // @Query("SELECT o FROM OtpGen o WHERE o.userId = :userId AND o.isActive = true")
    // Optional<OtpGen> findActiveOtpByUserId(@Param("userId") int userId);
}
