package com.mpsp.cc_auth_service.feignclients;

import com.mpsp.cc_auth_service.dto.Notification;
import feign.Headers;
import java.util.logging.Logger;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "notificationServiceClient", url = "${notification.service.url}")
@Headers("X-DRONARJUN-SOURCE: cc-auth-service")
public interface NotificationServiceClient {
  Logger logger = Logger.getLogger(NotificationServiceClient.class.getName());

  @PostMapping("/api/v1/notifications/send")
  void sendNotification(@RequestBody final Notification body);
}
