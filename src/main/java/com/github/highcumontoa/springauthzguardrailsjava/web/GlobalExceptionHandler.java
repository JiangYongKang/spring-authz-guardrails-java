package com.github.highcumontoa.springauthzguardrailsjava.web;

import com.github.highcumontoa.springauthzguardrailsjava.security.GuardrailRejectionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(GuardrailRejectionException.class)
    public ResponseEntity<ApiError> handleGuardrailRejection(GuardrailRejectionException ex) {
        log.warn("控制器层拒绝 reason={} basis={}", ex.getReason(), ex.getMessage());
        return ResponseEntity.status(ex.getHttpStatus())
                .body(new ApiError(ex.getReason().name(), ex.getMessage(), ex.getHttpStatus()));
    }
}
