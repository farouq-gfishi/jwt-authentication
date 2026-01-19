package com.jwt.jwttest.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.time.LocalDateTime;

import static org.springframework.http.HttpStatus.FORBIDDEN;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        LocalDateTime currentDateTime = LocalDateTime.now();
        String message = accessDeniedException.getMessage() != null ? accessDeniedException.getMessage() : "Authorization Failed";
        String path = request.getRequestURI();
        response.setHeader("jwt-test-error", "authorization failed");
        response.setStatus(FORBIDDEN.value());
        response.setContentType("application/json;charset=UTF-8");
        String jsonResponse =
                String.format("{\"timestamp\": \"%s\", \"status\": \"%s\", \"error\": \"%s\", \"message\": \"%s\", \"path\": \"%s\"}",
                        currentDateTime, FORBIDDEN.value(), FORBIDDEN.getReasonPhrase(), message, path);
        response.getWriter().write(jsonResponse);
    }
}
