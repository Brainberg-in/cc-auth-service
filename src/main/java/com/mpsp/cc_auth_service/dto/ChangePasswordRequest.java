package com.mpsp.cc_auth_service.dto;


import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ChangePasswordRequest extends ResetPasswordRequest{

    @Schema(description = "User Current Password")
    @NotBlank(message = " Current Password is required")
    private String currentPassword;


    @Override
    public String toString() {
        return String.format("ChangePasswordRequest[oldPassword=%s, password=%s]", "********", "********");
    }
}