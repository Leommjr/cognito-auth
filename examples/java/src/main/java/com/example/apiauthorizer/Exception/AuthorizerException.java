package com.example.apiauthorizer.Exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class AuthorizerException extends RuntimeException {
    public AuthorizerException(String message) {
        super(message);
    }
}
