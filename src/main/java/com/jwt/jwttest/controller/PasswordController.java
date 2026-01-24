package com.jwt.jwttest.controller;

import com.jwt.jwttest.entity.Customer;
import com.jwt.jwttest.model.ChangePasswordRequest;
import com.jwt.jwttest.repository.CustomerRepository;
import com.jwt.jwttest.service.EmailService;
import com.jwt.jwttest.service.JWTService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/password")
public class PasswordController {

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final EmailService emailService;

    public PasswordController(CustomerRepository customerRepository,
                              PasswordEncoder passwordEncoder,
                              JWTService jwtService,
                              EmailService emailService) {
        this.customerRepository = customerRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.emailService = emailService;
    }

    @PostMapping("/change")
    public ResponseEntity<String> change(@RequestBody ChangePasswordRequest request) {
        Customer customer = customerRepository.findByEmail(request.email())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(request.oldPassword(), customer.getPassword())) {
            return ResponseEntity.badRequest().body("Invalid old password");
        }

        customer.setPassword(passwordEncoder.encode(request.newPassword()));
        customer.setTokenVersion(customer.getTokenVersion() + 1);
        customerRepository.save(customer);

        return ResponseEntity.ok("Password changed");
    }

    @PostMapping("/request-reset")
    public ResponseEntity<String> requestReset(@RequestBody Map<String, String> request) {
        Customer customer = customerRepository.findByEmail(request.get("email"))
                .orElseThrow(() -> new RuntimeException("User not found"));

        String token = jwtService.generateEmailToken(customer.getEmail());
        customer.setVerificationToken(token);
        customerRepository.save(customer);

        emailService.sendForgotPasswordEmail(customer.getEmail(), token);
        return ResponseEntity.ok("Reset email sent");
    }

    @PostMapping("/reset")
    public ResponseEntity<String> reset(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String email = jwtService.extractEmail(token);

        Customer customer = customerRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!token.equals(customer.getVerificationToken()) || jwtService.isTokenExpired(token)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid token");
        }

        customer.setPassword(passwordEncoder.encode(request.get("newPassword")));
        customer.setVerificationToken(null);
        customer.setTokenVersion(customer.getTokenVersion() + 1);
        customerRepository.save(customer);

        return ResponseEntity.ok("Password reset");
    }
}

