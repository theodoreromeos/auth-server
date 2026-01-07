package com.theodore.auth.server.exceptions;

public class UnverifiedAccountException extends RuntimeException {

    public UnverifiedAccountException() {
        super("Email is not yet verified");
    }

}
