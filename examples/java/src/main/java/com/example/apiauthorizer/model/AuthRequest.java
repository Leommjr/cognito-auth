package com.example.apiauthorizer.model;

public class AuthRequest {

    private String accessToken;
    private String method;

    public AuthRequest() {}
    public AuthRequest(String accessToken, String method) {
        this.accessToken = accessToken;
        this.method = method;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }
}
