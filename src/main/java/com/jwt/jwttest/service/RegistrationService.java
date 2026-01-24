package com.jwt.jwttest.service;

import com.jwt.jwttest.entity.Authority;
import com.jwt.jwttest.entity.Customer;
import com.jwt.jwttest.exception.InvalidTokenException;
import com.jwt.jwttest.exception.UserAlreadyExistsException;
import com.jwt.jwttest.repository.CustomerRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Slf4j
public class RegistrationService {

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final EmailService emailService;

    public RegistrationService(CustomerRepository customerRepository,
                               PasswordEncoder passwordEncoder,
                               JWTService jwtService,
                               EmailService emailService) {
        this.customerRepository = customerRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.emailService = emailService;
    }

    @Transactional
    public void registerCustomer(Customer customer) {
        log.info("Registration requested for email: {}", customer.getEmail());

        if (customerRepository.findByEmail(customer.getEmail()).isPresent()) {
            log.warn("Registration failed - user already exists: {}", customer.getEmail());
            throw new UserAlreadyExistsException(customer.getEmail());
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
        log.info("Customer registered successfully: {}", customer.getEmail());
    }

    @Transactional
    public void verifyEmail(String token) {
        log.info("Email verification requested");
        String email = jwtService.extractEmail(token);
        Customer customer = customerRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidTokenException("Invalid verification token"));

        if (jwtService.isTokenExpired(token) || !token.equals(customer.getVerificationToken())) {
            log.warn("Invalid or expired verification token for email: {}", email);
            throw new InvalidTokenException("Token is invalid or expired");
        }

        customer.setVerified(true);
        customer.setVerificationToken(null);
        customerRepository.save(customer);
        log.info("Email verified successfully: {}", email);
    }
}