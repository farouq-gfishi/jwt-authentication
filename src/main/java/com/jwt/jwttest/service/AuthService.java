package com.jwt.jwttest.service;

import com.jwt.jwttest.domain.entity.Customer;
import com.jwt.jwttest.domain.dto.request.LoginRequest;
import com.jwt.jwttest.domain.dto.response.LoginResponse;
import com.jwt.jwttest.security.service.JWTService;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import static com.jwt.jwttest.constant.ApplicationConstant.USERNAME;

@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;
    private final CustomerService customerService;

    public AuthService(AuthenticationManager authenticationManager,
                       JWTService jwtService,
                       CustomerService customerService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.customerService = customerService;
    }

    public LoginResponse login(LoginRequest request) {
        log.info("Login attempt for email: {}", request.email());
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        log.info("Login successful for email: {}", request.email());
        return new LoginResponse(
                jwtService.generateAccessToken(auth),
                jwtService.generateRefreshToken(auth)
        );
    }

    public LoginResponse refreshToken(String refreshToken) {
        log.info("Token refresh requested");
        Claims claims = jwtService.validateRefreshToken(refreshToken);
        String email = claims.get(USERNAME, String.class);
        Integer tokenVersion = claims.get("tv", Integer.class);

        Customer customer = customerService.findByEmail(email);

        if (!customer.getEnabled() || !tokenVersion.equals(customer.getTokenVersion())) {
            log.warn("Token refresh failed - token revoked for email: {}", email);
            throw new BadCredentialsException("Token has been revoked");
        }

        Authentication auth = new UsernamePasswordAuthenticationToken(
                email,
                null,
                customer.getAuthorities()
                        .stream()
                        .map(a -> new SimpleGrantedAuthority(a.getName()))
                        .toList()
        );

        log.info("Token refreshed successfully for email: {}", email);
        return new LoginResponse(
                jwtService.generateAccessToken(auth, tokenVersion),
                jwtService.generateRefreshToken(auth, tokenVersion)
        );
    }
}