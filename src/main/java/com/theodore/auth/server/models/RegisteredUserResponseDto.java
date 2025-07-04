package com.theodore.auth.server.models;

public class RegisteredUserResponseDto {

    private final String email;
    private final String phoneNumber;

    public RegisteredUserResponseDto(String email, String phoneNumber) {
        this.email = email;
        this.phoneNumber = phoneNumber;
    }

    public String getEmail() {
        return email;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }
}
