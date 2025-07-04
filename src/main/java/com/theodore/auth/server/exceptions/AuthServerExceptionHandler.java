package com.theodore.auth.server.exceptions;

import com.theodore.racingmodel.exceptions.NotFoundException;
import com.theodore.racingmodel.exceptions.UserAlreadyExistsException;
import com.theodore.racingmodel.models.MobilityAppErrorResponse;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.stream.Collectors;

@RestControllerAdvice
public class AuthServerExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(AuthServerExceptionHandler.class);

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<MobilityAppErrorResponse> handleUserAlreadyExistsErrors(UserAlreadyExistsException ex) {

        logger.warn("User with email {} already exists.", ex.getEmail(), ex);

        return new ResponseEntity<>(HttpStatus.CONFLICT);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<MobilityAppErrorResponse> handleValidationErrors(MethodArgumentNotValidException ex) {

        String fieldErrors = ex.getBindingResult().getFieldErrors().stream()
                .map(err -> err.getField() + ": " + err.getDefaultMessage())
                .collect(Collectors.joining("; "));

        logger.warn("Validation failed [{}]: {}", ex.getBindingResult().getObjectName(), fieldErrors, ex);

        String userMessage = getExceptionMessage(ex.getBindingResult(), "Bad Request");

        MobilityAppErrorResponse error = new MobilityAppErrorResponse(userMessage, Instant.now());

        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<MobilityAppErrorResponse> handleNotFoundErrors(NotFoundException ex) {

        logger.warn("Resource not found: {}", ex.getMessage(), ex);

        MobilityAppErrorResponse error = new MobilityAppErrorResponse(ex.getMessage(), Instant.now());

        return new ResponseEntity<>(error, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<MobilityAppErrorResponse> handleGeneral(Exception ex) {

        logger.error("Unexpected error occurred: {}", ex.getMessage(), ex);

        MobilityAppErrorResponse error = new MobilityAppErrorResponse("Unexpected error occurred", Instant.now());

        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private String getExceptionMessage(BindingResult bindingResult, String alternativeMessage) {
        return bindingResult
                .getFieldErrors()
                .stream()
                .map(FieldError::getDefaultMessage)
                .toList()
                .stream().findFirst().orElse(alternativeMessage);
    }


}
