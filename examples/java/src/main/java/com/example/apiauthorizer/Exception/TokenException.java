package com.example.apiauthorizer.Exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Classe genérica para exceções de autorização
 */
public class TokenException extends Exception {
    public TokenException(String message){
        super(message);
    }
}
