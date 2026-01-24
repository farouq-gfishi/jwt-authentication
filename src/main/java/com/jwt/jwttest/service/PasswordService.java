package com.jwt.jwttest.service;

import com.jwt.jwttest.entity.Customer;
import com.jwt.jwttest.exception.InvalidPasswordException;
import com.jwt.jwttest.exception.InvalidTokenException;
import com.jwt.jwttest.model.ChangePasswordRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
public class PasswordService {

    private final CustomerService customerService;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final EmailService emailService;

    public PasswordService(CustomerService customerService,
                           PasswordEncoder passwordEncoder,
                           JWTService jwtService,
                           EmailService emailService) {
        this.customerService = customerService;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.emailService = emailService;
    }

    @Transactional
    public void changePassword(ChangePasswordRequest request) {
        log.info("Password change requested for email: {}", request.email());
        Customer customer = customerService.findByEmail(request.email());

        if (!passwordEncoder.matches(request.oldPassword(), customer.getPassword())) {
            log.warn("Invalid old password provided for email: {}", request.email());
            throw new InvalidPasswordException("Old password is incorrect");
        }

        customer.setPassword(passwordEncoder.encode(request.newPassword()));
        customerService.incrementTokenVersion(customer);
        log.info("Password changed successfully for email: {}", request.email());
    }

    @Transactional
    public void requestPasswordReset(String email) {
        log.info("Password reset requested for email: {}", email);
        Customer customer = customerService.findByEmail(email);
        String token = jwtService.generateEmailToken(email);
        customer.setVerificationToken(token);
        customerService.save(customer);
        emailService.sendForgotPasswordEmail(email, token);
        log.info("Password reset email sent to: {}", email);
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        log.info("Processing password reset with token");
        String email = jwtService.extractEmail(token);
        Customer customer = customerService.findByEmail(email);

        if (!token.equals(customer.getVerificationToken()) || jwtService.isTokenExpired(token)) {
            log.warn("Invalid or expired token used for password reset: {}", email);
            throw new InvalidTokenException("Token is invalid or expired");
        }

        customer.setPassword(passwordEncoder.encode(newPassword));
        customer.setVerificationToken(null);
        customerService.incrementTokenVersion(customer);
        log.info("Password reset successfully for email: {}", email);
    }
}