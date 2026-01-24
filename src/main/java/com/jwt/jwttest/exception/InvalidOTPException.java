package com.jwt.jwttest.exception;

public class InvalidOTPException extends RuntimeException {
    public InvalidOTPException() {
        super("Invalid or expired OTP code");
    }
}
