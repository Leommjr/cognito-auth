package com.example.apiauthorizer.controller;

import com.example.apiauthorizer.Exception.RefreshException;
import com.example.apiauthorizer.Exception.ResetException;
import com.example.apiauthorizer.Exception.TokenException;
import com.example.apiauthorizer.model.UserLogin;
import com.example.apiauthorizer.model.UserPool;
import com.example.apiauthorizer.model.UserRefresh;
import com.example.apiauthorizer.model.UserReset;
import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.apiauthorizer.service.CognitoAuthService;

import javax.security.auth.login.LoginException;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
public class CognitoAuthController {
    UserPool pool = new UserPool();

    @PostMapping(path= "/api/login", consumes = APPLICATION_JSON_VALUE, produces= APPLICATION_JSON_VALUE)
    public ResponseEntity<String> login(@RequestBody UserLogin user) throws LoginException {
        try {
            return new ResponseEntity<String>(new CognitoAuthService(pool.getUserPoolId(), pool.getClientId()).login(user.getUsername(), user.getPassword(), user.getPassword()), HttpStatus.OK);

        }catch (Exception e) {
            throw new LoginException(e.getMessage());
        }
    }
    @PostMapping(path= "/api/reset", produces= APPLICATION_JSON_VALUE)
    public ResponseEntity<String> reset(@RequestBody UserReset reset) throws ResetException {
        try {
            return new ResponseEntity<String>(new CognitoAuthService(pool.getUserPoolId(), pool.getClientId()).reset(reset.getUsername(), reset.getCode(), reset.getNewPassword()), HttpStatus.OK);
        }catch (Exception e) {
            throw new ResetException(e.getMessage());
        }
    }
    @PostMapping(path= "/api/refresh", produces= APPLICATION_JSON_VALUE)
    public ResponseEntity<String> refresh(@RequestBody UserRefresh refresh) throws RefreshException {
        try {
            return new ResponseEntity<String>(new CognitoAuthService(pool.getUserPoolId(), pool.getClientId()).refresh(refresh.getRefreshToken()),HttpStatus.OK);
        }catch (Exception e) {
            throw new RefreshException(e.getMessage());
        }
    }
}
