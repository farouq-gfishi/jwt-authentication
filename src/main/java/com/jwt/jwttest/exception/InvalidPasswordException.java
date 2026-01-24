package com.jwt.jwttest.exception;

public class InvalidPasswordException extends RuntimeException {
    public InvalidPasswordException(String email) {
        super("Invalid password: " + email);
    }
}
