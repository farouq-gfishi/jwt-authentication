package com.jwt.jwttest.controller.auth;

import com.jwt.jwttest.domain.dto.request.LoginRequest;
import com.jwt.jwttest.domain.dto.response.LoginResponse;
import com.jwt.jwttest.domain.dto.request.RefreshTokenRequest;
import com.jwt.jwttest.service.AuthService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/refresh-token")
    public LoginResponse refresh(@RequestBody RefreshTokenRequest request) {
        return authService.refreshToken(request.refreshToken());
    }
}