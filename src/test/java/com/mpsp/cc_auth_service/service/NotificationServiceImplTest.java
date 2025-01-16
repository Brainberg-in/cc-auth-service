package com.mpsp.cc_auth_service.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.mpsp.cc_auth_service.dto.Notification;
import com.mpsp.cc_auth_service.feignclients.NotificationServiceClient;
import com.mpsp.cc_auth_service.service.impl.NotificationServiceImpl;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class NotificationServiceImplTest {

  @Mock private NotificationServiceClient notificationServiceClient;

  @InjectMocks private NotificationServiceImpl notificationService;

  private Map<String, String> dataMap;
  private static final String MODE = "EMAIL";
  private static final String TEMPLATE_NAME = "OTP_TEMPLATE";
  private static final String EMAIL_RECEIVER = "test@example.com";
  private static final String SMS_RECEIVER = "+1234567890";

  @BeforeEach
  void setUp() {
    dataMap = new HashMap<>();
    dataMap.put("otp", "123456");
    dataMap.put("userName", "Test User");
  }

  @Test
  void sendNotification_ShouldCallNotificationServiceClient() throws InterruptedException {
    // Given
    doNothing().when(notificationServiceClient).sendNotification(any(Notification.class));

    // When
    notificationService.sendNotification(
        MODE, TEMPLATE_NAME, EMAIL_RECEIVER, SMS_RECEIVER, dataMap);

    // Then
    // Since the method is @Async, we need to wait a bit for the async operation to complete
    TimeUnit.MILLISECONDS.sleep(100);

    verify(notificationServiceClient)
        .sendNotification(
            argThat(
                notification ->
                    notification.getMode().equals(MODE)
                        && notification.getTemplateName().equals(TEMPLATE_NAME)
                        && notification.getEmailReceiver().equals(EMAIL_RECEIVER)
                        && notification.getSmsReceiver().equals(SMS_RECEIVER)
                        && notification.getDataMap().equals(dataMap)));
  }

  @Test
  void sendNotification_WithNullValues_ShouldStillCallService() throws InterruptedException {
    // Given
    doNothing().when(notificationServiceClient).sendNotification(any(Notification.class));

    // When
    notificationService.sendNotification(
        MODE,
        TEMPLATE_NAME,
        null, // null email
        null, // null SMS
        null // null dataMap
        );

    // Then
    TimeUnit.MILLISECONDS.sleep(100);

    verify(notificationServiceClient)
        .sendNotification(
            argThat(
                notification ->
                    notification.getMode().equals(MODE)
                        && notification.getTemplateName().equals(TEMPLATE_NAME)
                        && notification.getEmailReceiver() == null
                        && notification.getSmsReceiver() == null
                        && notification.getDataMap() == null));
  }
}
