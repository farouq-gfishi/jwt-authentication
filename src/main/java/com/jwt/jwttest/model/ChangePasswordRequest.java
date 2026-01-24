package com.jwt.jwttest.model;

public record ChangePasswordRequest(String phoneNumber, String oldPassword, String newPassword) {
}
