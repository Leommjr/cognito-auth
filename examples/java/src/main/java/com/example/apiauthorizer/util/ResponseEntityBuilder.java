package com.example.apiauthorizer.util;

import com.example.apiauthorizer.model.ApiError;
import  org.springframework.http.ResponseEntity;

public class ResponseEntityBuilder {
    public static ResponseEntity<Object> build(ApiError apiError) {
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }
}