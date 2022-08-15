package com.example.apiauthorizer.Exception;

import com.example.apiauthorizer.model.ApiError;
import com.example.apiauthorizer.util.ResponseEntityBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;


import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(LoginException.class)
    public ResponseEntity<Object> handleLoginException(LoginException ex){
        List<String> details = new ArrayList<String>();
        details.add(ex.getMessage());

        ApiError err = new ApiError(
                LocalDateTime.now(),
                HttpStatus.BAD_REQUEST,
                "Error while sign in" ,
                details);

        return ResponseEntityBuilder.build(err);
    }
    @ExceptionHandler(ResetException.class)
    public ResponseEntity<Object> handleResetException(ResetException ex){
        List<String> details = new ArrayList<String>();
        details.add(ex.getMessage());

        ApiError err = new ApiError(
                LocalDateTime.now(),
                HttpStatus.BAD_REQUEST,
                "Error while reseting password" ,
                details);

        return ResponseEntityBuilder.build(err);
    }
    @ExceptionHandler(RefreshException.class)
    public ResponseEntity<Object> handleRefreshException(RefreshException ex){
        List<String> details = new ArrayList<String>();
        details.add(ex.getMessage());

        ApiError err = new ApiError(
                LocalDateTime.now(),
                HttpStatus.BAD_REQUEST,
                "Error while refreshing token" ,
                details);

        return ResponseEntityBuilder.build(err);
    }

    @ExceptionHandler(AuthorizerException.class)
    public ResponseEntity<Object> handleAuthorizeException(AuthorizerException ex){
        List<String> details = new ArrayList<String>();
        details.add(ex.getMessage());

        ApiError err = new ApiError(
                LocalDateTime.now(),
                HttpStatus.UNAUTHORIZED,
                "Permission Denied!" ,
                details);

        return ResponseEntityBuilder.build(err);
    }


    @ExceptionHandler({ Exception.class })
    public ResponseEntity<Object> handleAll(Exception ex, WebRequest request) {

        List<String> details = new ArrayList<String>();
        details.add(ex.getLocalizedMessage());

        ApiError err = new ApiError(LocalDateTime.now(),HttpStatus.BAD_REQUEST, "Error occurred" ,details);

        return ResponseEntityBuilder.build(err);

    }
}
