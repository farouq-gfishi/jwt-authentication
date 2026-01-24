package com.jwt.jwttest.controller;

import com.jwt.jwttest.entity.Customer;
import com.jwt.jwttest.model.LoginRequest;
import com.jwt.jwttest.model.LoginResponse;
import com.jwt.jwttest.repository.CustomerRepository;
import com.jwt.jwttest.service.JWTService;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static com.jwt.jwttest.constant.ApplicationConstant.USERNAME;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;
    private final CustomerRepository customerRepository;

    public AuthController(AuthenticationManager authenticationManager,
                          JWTService jwtService,
                          CustomerRepository customerRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.customerRepository = customerRepository;
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest request) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        return new LoginResponse(
                jwtService.generateAccessToken(auth),
                jwtService.generateRefreshToken(auth)
        );
    }

    @PostMapping("/refresh-token")
    public LoginResponse refresh(@RequestBody Map<String, String> request) {
        Claims claims = jwtService.validateRefreshToken(request.get("refreshToken"));
        String email = claims.get(USERNAME, String.class);
        Integer tv = claims.get("tv", Integer.class);

        Customer customer = customerRepository.findByEmail(email)
                .orElseThrow(() -> new BadCredentialsException("User not found"));

        if (!customer.getEnabled() || !tv.equals(customer.getTokenVersion())) {
            throw new BadCredentialsException("Token revoked");
        }

        Authentication auth = new UsernamePasswordAuthenticationToken(
                email,
                null,
                customer.getAuthorities()
                        .stream()
                        .map(a -> new SimpleGrantedAuthority(a.getName()))
                        .toList()
        );

        return new LoginResponse(
                jwtService.generateAccessToken(auth, tv),
                jwtService.generateRefreshToken(auth, tv)
        );
    }
}

