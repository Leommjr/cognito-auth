package com.example.apiauthorizer.model;

public class UserRefresh {

    private String refreshToken;

    public UserRefresh(){}

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
