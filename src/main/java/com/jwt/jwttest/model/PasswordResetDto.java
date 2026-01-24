package com.jwt.jwttest.model;

public record PasswordResetDto(String token, String newPassword) {
}
