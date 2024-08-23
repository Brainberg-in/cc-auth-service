package com.mpsp.cc_auth_service.dto;

public class LoginResponse {
    private String token;
    private String refreshToken;


    public LoginResponse(String token, String refreshToken) {
        this.token = token;
        this.refreshToken = refreshToken;
    }

    public String getToken() {
        return token;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
