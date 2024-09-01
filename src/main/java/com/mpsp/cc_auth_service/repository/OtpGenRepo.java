package com.mpsp.cc_auth_service.repository;

import com.mpsp.cc_auth_service.entity.OtpGen;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OtpGenRepo extends JpaRepository<OtpGen, Long> {
  Optional<OtpGen> findByUserId(Integer userId);
}
