package com.jwt.jwttest.domain.dto.request;

public record ChangePasswordRequest(String email, String oldPassword, String newPassword) {
}
