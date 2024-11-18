package com.mpsp.cc_auth_service.dto;
import java.util.Map;

import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Notification {
    @Pattern(regexp = "mobile|email|both", message = "Invalid mode")
    private String mode;

    private String templateName;
    private String emailReceiver;
    private String smsReceiver;
    private Map<String, String> dataMap;
}
