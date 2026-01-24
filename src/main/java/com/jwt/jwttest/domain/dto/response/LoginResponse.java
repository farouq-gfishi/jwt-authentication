package com.jwt.jwttest.domain.dto.response;

public record LoginResponse(String accessToken, String refreshToken) {
}
