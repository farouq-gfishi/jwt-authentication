package com.jwt.jwttest.domain.dto.request;

public record PasswordResetDto(String token, String newPassword) {
}
