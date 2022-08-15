package com.example.apiauthorizer.model;

import com.example.apiauthorizer.util.Util;

import java.util.Properties;

public class UserPool {

    private String userPoolId;
    private String clientId;
    private String region;

    public UserPool() {
        Properties prop = Util.fetchProperties();
        this.userPoolId = prop.getProperty("USERPOOL_ID");
        this.region = prop.getProperty("REGION", "sa-east-1");
        this.clientId = prop.getProperty("CLIENT_ID");
    }

    public String getUserPoolId() {
        return userPoolId;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRegion() {
        return region;
    }
}
