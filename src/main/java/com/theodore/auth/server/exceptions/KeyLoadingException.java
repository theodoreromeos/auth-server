package com.theodore.auth.server.exceptions;

public class KeyLoadingException extends RuntimeException {

    public KeyLoadingException(String msg, Throwable throwable) {
        super(msg, throwable);
    }
}
