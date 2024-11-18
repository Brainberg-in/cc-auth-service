package com.mpsp.cc_auth_service.service.impl;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.stereotype.Service;

import com.mpsp.cc_auth_service.dto.Notification;
import com.mpsp.cc_auth_service.feignclients.NotificationServiceClient;
import com.mpsp.cc_auth_service.service.NotificationService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class NotificationServiceImpl implements NotificationService {

    @Autowired private transient NotificationServiceClient notificationService;

    @Override
    @Transactional
    public void sendNotification(String mode, String templateName, String emailReceiver, String smsReceiver, Map<String, String> dataMap) {
        Notification notification = new Notification();
        
        notification.setMode(mode);
        notification.setTemplateName(templateName);
        notification.setEmailReceiver(emailReceiver);
        notification.setSmsReceiver(smsReceiver);
        notification.setDataMap(dataMap);

        notificationService.sendNotification(notification);
    }
}
