package com.jwt.jwttest.controller.auth;

import com.jwt.jwttest.domain.entity.Customer;
import com.jwt.jwttest.domain.dto.request.OTPRequest;
import com.jwt.jwttest.domain.dto.request.ResendOTPRequest;
import com.jwt.jwttest.service.OTPService;
import com.jwt.jwttest.service.RegistrationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class RegistrationController {

    private final RegistrationService registrationService;
    private final OTPService otpService;

    public RegistrationController(RegistrationService registrationService,
                                  OTPService otpService) {
        this.registrationService = registrationService;
        this.otpService = otpService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody Customer customer) {
        registrationService.registerCustomer(customer);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body("Registration successful. Please check your email for verification.");
    }

    @GetMapping("/verify-email")
    public ResponseEntity<String> verify(@RequestParam String token) {
        registrationService.verifyEmail(token);
        return ResponseEntity.ok("Email verified successfully");
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<String> verifyOtp(@RequestBody OTPRequest request) {
        otpService.verifyOTP(request);
        return ResponseEntity.ok("OTP verified successfully");
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<String> resend(@RequestBody ResendOTPRequest request) {
        otpService.sendOTP(request.phoneNumber());
        return ResponseEntity.ok("OTP sent successfully");
    }
}