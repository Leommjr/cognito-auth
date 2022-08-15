package com.example.apiauthorizer.controller;


import com.example.apiauthorizer.Exception.AuthorizerException;
import com.example.apiauthorizer.service.AuthorizerService;
import com.example.apiauthorizer.util.JwtVerifierUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.json.JSONObject;

@RestController
public class UserController {

    @GetMapping(path= "/api/users/getAll", produces= MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getUsers(@RequestHeader(value = "Authorization", required = false) String authToken) {
        JSONObject jresult = new JSONObject();
        try {
            String accessToken = authToken.substring(7);
            AuthorizerService.authorize(accessToken, "GET");
            return new ResponseEntity<String>("YES", HttpStatus.OK);
        } catch (Exception e) {
            throw new AuthorizerException(e.getMessage());
        }
    }
}
