package com.mpsp.cc_auth_service.feignclients;

import java.util.logging.Logger;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.mpsp.cc_auth_service.dto.Notification;

@FeignClient(name = "notificationServiceClient", url = "${notification.service.url}")
public interface NotificationServiceClient {
    Logger logger = Logger.getLogger(NotificationServiceClient.class.getName());

    @PostMapping("/api/v1/notifications/send")
    void sendNotification(
        @RequestBody final Notification body);
}
