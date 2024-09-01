package com.mpsp.cc_auth_service.service;

import java.util.Map;

public interface AwsService {
  void sendEmail(
      String sender, String recipient, String templateName, Map<String, String> objectMap);
}
