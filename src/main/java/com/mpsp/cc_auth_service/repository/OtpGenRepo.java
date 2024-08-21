package com.mpsp.cc_auth_service.repository;

import com.mpsp.cc_auth_service.entity.OtpGen;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OtpGenRepo extends JpaRepository<OtpGen, Long> {
    OtpGen findByUserId(Integer userId);
}
