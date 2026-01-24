package com.jwt.jwttest.controller;

import com.jwt.jwttest.entity.Authority;
import com.jwt.jwttest.entity.Customer;
import com.jwt.jwttest.model.OTPRequest;
import com.jwt.jwttest.repository.CustomerRepository;
import com.jwt.jwttest.service.EmailService;
import com.jwt.jwttest.service.JWTService;
import com.jwt.jwttest.service.OTPService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/auth")
public class RegistrationController {

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final EmailService emailService;
    private final OTPService otpService;

    public RegistrationController(CustomerRepository customerRepository,
                                  PasswordEncoder passwordEncoder,
                                  JWTService jwtService,
                                  EmailService emailService,
                                  OTPService otpService) {
        this.customerRepository = customerRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.emailService = emailService;
        this.otpService = otpService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody Customer customer) {
        if (customerRepository.findByEmail(customer.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body("User already exists");
        }

        customer.setPassword(passwordEncoder.encode(customer.getPassword()));

        Authority authority = new Authority();
        authority.setName("ROLE_USER");
        authority.setCustomer(customer);
        customer.setAuthorities(Set.of(authority));

        String token = jwtService.generateEmailToken(customer.getEmail());
        customer.setVerificationToken(token);

        customerRepository.save(customer);
        emailService.sendVerificationEmail(customer.getEmail(), token);

        return ResponseEntity.status(HttpStatus.CREATED).body("Registered successfully");
    }

    @GetMapping("/verify-email")
    public ResponseEntity<String> verify(@RequestParam String token) {
        String email = jwtService.extractEmail(token);

        Customer customer = customerRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (jwtService.isTokenExpired(token) || !token.equals(customer.getVerificationToken())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Token expired");
        }

        customer.setVerified(true);
        customer.setVerificationToken(null);
        customerRepository.save(customer);

        return ResponseEntity.ok("Email verified");
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<String> verifyOtp(@RequestBody OTPRequest request) {
        otpService.verifyOTP(request);
        return ResponseEntity.ok("OTP verified");
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<String> resend(@RequestBody Map<String, String> request) {
        otpService.sendOTP(request.get("phoneNumber"));
        return ResponseEntity.ok("OTP sent");
    }
}

