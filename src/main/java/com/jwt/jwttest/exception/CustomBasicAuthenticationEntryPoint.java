package com.jwt.jwttest.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.time.LocalDateTime;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

public class CustomBasicAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException {
        LocalDateTime currentDateTime = LocalDateTime.now();
        String message = authException.getMessage() != null ? authException.getMessage() : "Authentication Failed";
        String path = request.getRequestURI();
        response.setHeader("jwt-test-error", "authentication failed");
        response.setStatus(UNAUTHORIZED.value());
        response.setContentType("application/json;charset=UTF-8");
        String jsonResponse =
                String.format("{\"timestamp\": \"%s\", \"status\": \"%s\", \"error\": \"%s\", \"message\": \"%s\", \"path\": \"%s\"}",
                        currentDateTime, UNAUTHORIZED.value(), UNAUTHORIZED.getReasonPhrase(), message, path);
        response.getWriter().write(jsonResponse);
    }
}
