package com.jwt.jwttest.exception.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.jwttest.domain.dto.response.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.time.LocalDateTime;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

public class CustomBasicAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        ErrorResponse errorResponse = new ErrorResponse(
                LocalDateTime.now(),
                UNAUTHORIZED.value(),
                UNAUTHORIZED.getReasonPhrase(),
                authException.getMessage() != null ?
                        authException.getMessage() : "Authentication failed. Please provide valid credentials.",
                request.getRequestURI()
        );
        response.setHeader("jwt-test-error", "authentication failed");
        response.setStatus(UNAUTHORIZED.value());
        response.setContentType("application/json;charset=UTF-8");
        objectMapper.registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}