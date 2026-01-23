package com.jwt.jwttest.controller;

import com.jwt.jwttest.entity.Authority;
import com.jwt.jwttest.entity.Customer;
import com.jwt.jwttest.model.LoginRequest;
import com.jwt.jwttest.model.LoginResponse;
import com.jwt.jwttest.repository.CustomerRepository;
import com.jwt.jwttest.service.JWTService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
public class CustomerController {

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;

    public CustomerController(CustomerRepository customerRepository,
                              PasswordEncoder passwordEncoder,
                              AuthenticationManager authenticationManager,
                              JWTService jwtService) {
        this.customerRepository = customerRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
        customer.setPassword(passwordEncoder.encode(customer.getPassword()));
        Authority authority = new Authority();
        authority.setName("ROLE_USER");
        authority.setCustomer(customer);
        customer.setAuthorities(Set.of(authority));
        customerRepository.save(customer);
        return ResponseEntity.status(HttpStatus.CREATED).body("created successfully");
    }

    @PostMapping("/getToken")
    public LoginResponse getToken(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String accessToken = jwtService.generateAccessToken(authentication);
        String refreshToken = jwtService.generateRefreshToken(authentication);
        return new LoginResponse(accessToken, refreshToken);
    }

    @PostMapping("/refreshToken")
    public LoginResponse refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        String username = jwtService.validateRefreshTokenAndGetUsername(refreshToken);
        Customer customer = customerRepository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        List<GrantedAuthority> authorities = customer.getAuthorities()
                .stream()
                .map(a -> new SimpleGrantedAuthority(a.getName()))
                .collect(Collectors.toList());
        Authentication auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
        String newAccessToken = jwtService.generateAccessToken(auth);
        String newRefreshToken = jwtService.generateRefreshToken(auth);

        return new LoginResponse(newAccessToken, newRefreshToken);
    }

}
