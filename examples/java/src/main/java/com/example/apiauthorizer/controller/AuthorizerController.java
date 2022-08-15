package com.example.apiauthorizer.controller;

import com.example.apiauthorizer.Exception.AuthorizerException;
import com.example.apiauthorizer.model.AuthRequest;
import com.example.apiauthorizer.model.UserLogin;
import com.example.apiauthorizer.service.AuthorizerService;
import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
public class AuthorizerController {
    @PostMapping(path= "/api/authorize", consumes = APPLICATION_JSON_VALUE, produces= MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> authorize(@RequestBody AuthRequest req) throws AuthorizerException {
        JSONObject jresult = new JSONObject();
        try {
            AuthorizerService.authorize(req.getAccessToken(), req.getMethod());
            jresult.put("Ok", "Permission granted");
            return new ResponseEntity<String>(jresult.toString(), HttpStatus.OK);
        } catch (Exception e) {
            throw new AuthorizerException(e.getMessage());
        }
    }
}
