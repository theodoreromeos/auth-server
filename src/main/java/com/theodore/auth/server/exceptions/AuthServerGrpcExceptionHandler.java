package com.theodore.auth.server.exceptions;

import com.theodore.racingmodel.exceptions.NotFoundException;
import com.theodore.racingmodel.exceptions.RollbackProcessingException;
import com.theodore.racingmodel.exceptions.UserAlreadyExistsException;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import net.devh.boot.grpc.server.advice.GrpcAdvice;
import net.devh.boot.grpc.server.advice.GrpcExceptionHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;

@GrpcAdvice
public class AuthServerGrpcExceptionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthServerGrpcExceptionHandler.class);

    @GrpcExceptionHandler(UserAlreadyExistsException.class)
    public StatusRuntimeException handleUserAlreadyExists(UserAlreadyExistsException ex) {
        LOGGER.warn("User with email {} already exists.", ex.getEmail(), ex);
        return Status.ALREADY_EXISTS.withDescription(ex.getMessage()).asRuntimeException();
    }

    @GrpcExceptionHandler(NotFoundException.class)
    public StatusRuntimeException handleNotFound(NotFoundException ex) {
        LOGGER.error("Resource not found: {}", ex.getMessage(), ex);
        return Status.NOT_FOUND.withDescription(ex.getMessage()).asRuntimeException();
    }

    @GrpcExceptionHandler(KeyLoadingException.class)
    public StatusRuntimeException handleKeyLoading(KeyLoadingException ex) {
        LOGGER.error("{}", ex.getMessage(), ex);
        return Status.INTERNAL.withDescription(ex.getMessage()).asRuntimeException();
    }

    @GrpcExceptionHandler(IllegalArgumentException.class)
    public StatusRuntimeException handleIllegalArgumentException(IllegalArgumentException ex) {
        LOGGER.error("{}", ex.getMessage(), ex);
        return Status.INVALID_ARGUMENT.withDescription(ex.getMessage()).asRuntimeException();
    }

    @GrpcExceptionHandler(BadCredentialsException.class)
    public StatusRuntimeException handleBadCredentialsException(BadCredentialsException ex) {
        LOGGER.error("{}", ex.getMessage(), ex);
        return Status.INVALID_ARGUMENT.withDescription(ex.getMessage()).asRuntimeException();
    }

    @GrpcExceptionHandler(RollbackProcessingException.class)
    public StatusRuntimeException handleBadCredentialsException(RollbackProcessingException ex) {
        LOGGER.error("{}", ex.getMessage(), ex);
        return Status.UNAVAILABLE.withDescription(ex.getMessage()).asRuntimeException();
    }

    @GrpcExceptionHandler(Exception.class)
    public StatusRuntimeException handleDefault(Exception ex) {
        LOGGER.error("Unexpected error occurred: {}", ex.getMessage(), ex);
        return Status.INTERNAL.withDescription("Unexpected error occurred").asRuntimeException();
    }
}
