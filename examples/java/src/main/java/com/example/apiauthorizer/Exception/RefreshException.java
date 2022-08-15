package com.example.apiauthorizer.Exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class RefreshException extends RuntimeException{
    public RefreshException(String message) {
        super(message);
    }
}
