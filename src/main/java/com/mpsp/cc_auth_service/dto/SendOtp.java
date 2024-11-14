package com.mpsp.cc_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SendOtp {
    @Pattern(regexp = "sms|email|both", message = "Invalid mode")
    private String mode;

    @Pattern(regexp = "login|register|forgotPassword|changePassword|verifyEmail|verifyMobile", message = "Invalid purpose")
    private String purpose;

    @JsonProperty("isResend")
    private boolean resend;
}
