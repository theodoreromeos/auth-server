package com.theodore.auth.server.exceptions;

public class RoleAlreadyAssignedException extends RuntimeException {

    public RoleAlreadyAssignedException() {
        super("Role already assigned");
    }

}
