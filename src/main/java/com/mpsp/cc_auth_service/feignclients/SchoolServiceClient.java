package com.mpsp.cc_auth_service.feignclients;

import com.mpsp.cc_auth_service.dto.SchoolDetails;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "schoolServiceClient", url = "${school.service.url}")
public interface SchoolServiceClient {

  @GetMapping("/api/v1/schools/{schoolId}")
  SchoolDetails getSchoolDetails(
      @PathVariable(name = "schoolId") final int schoolId,
      @RequestParam(name = "isVerified") final boolean isVerified);
}
