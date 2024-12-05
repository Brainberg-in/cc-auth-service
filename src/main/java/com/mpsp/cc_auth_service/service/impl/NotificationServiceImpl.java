package com.mpsp.cc_auth_service.service.impl;

import com.mpsp.cc_auth_service.dto.Notification;
import com.mpsp.cc_auth_service.feignclients.NotificationServiceClient;
import com.mpsp.cc_auth_service.service.NotificationService;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class NotificationServiceImpl implements NotificationService {

  @Autowired private transient NotificationServiceClient notificationService;

  @Override
  @Async
  public void sendNotification(
      final String mode,
      final String templateName,
      final String emailReceiver,
      final String smsReceiver,
      final Map<String, String> dataMap) {
    final Notification notification = new Notification();

    notification.setMode(mode);
    notification.setTemplateName(templateName);
    notification.setEmailReceiver(emailReceiver);
    notification.setSmsReceiver(smsReceiver);
    notification.setDataMap(dataMap);

    notificationService.sendNotification(notification);
  }
}
