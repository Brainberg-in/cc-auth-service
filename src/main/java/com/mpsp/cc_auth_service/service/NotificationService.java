package com.mpsp.cc_auth_service.service;

import java.util.Map;

public interface NotificationService {
    void sendNotification(
        String mode, String templateName, String emailReceiver, String smsReceiver, Map<String, String> dataMap);
}
