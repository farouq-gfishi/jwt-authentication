package com.jwt.jwttest.model;

public record ChangePasswordRequest(String email, String oldPassword, String newPassword) {
}
