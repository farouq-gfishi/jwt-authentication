package com.jwt.jwttest.controller;

import com.jwt.jwttest.entity.Authority;
import com.jwt.jwttest.entity.Customer;
import com.jwt.jwttest.model.LoginRequest;
import com.jwt.jwttest.model.LoginResponse;
import com.jwt.jwttest.model.OTPRequest;
import com.jwt.jwttest.repository.CustomerRepository;
import com.jwt.jwttest.service.JWTService;
import com.jwt.jwttest.service.OTPService;
import jakarta.transaction.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
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
    private final OTPService otpService;

    public CustomerController(CustomerRepository customerRepository,
                              PasswordEncoder passwordEncoder,
                              AuthenticationManager authenticationManager,
                              JWTService jwtService,
                              OTPService otpService) {
        this.customerRepository = customerRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.otpService = otpService;
    }

    @PostMapping("/register")
    @Transactional
    public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
        customer.setPassword(passwordEncoder.encode(customer.getPassword()));
        Authority authority = new Authority();
        authority.setName("ROLE_USER");
        authority.setCustomer(customer);
        customer.setAuthorities(Set.of(authority));
        customerRepository.save(customer);
        otpService.sendOTP(customer.getPhoneNumber());
        return ResponseEntity.status(HttpStatus.CREATED).body("created successfully");
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.phoneNumber(), loginRequest.password())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String accessToken = jwtService.generateAccessToken(authentication);
        String refreshToken = jwtService.generateRefreshToken(authentication);
        return new LoginResponse(accessToken, refreshToken);
    }

    @PostMapping("/refresh-token")
    public LoginResponse refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        String username = jwtService.validateRefreshTokenAndGetUsername(refreshToken);
        Customer customer = customerRepository.findByPhoneNumber(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        if (!customer.getEnabled()) {
            throw new BadCredentialsException("User is disabled");
        }
        List<GrantedAuthority> authorities = customer.getAuthorities()
                .stream()
                .map(a -> new SimpleGrantedAuthority(a.getName()))
                .collect(Collectors.toList());
        Authentication auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
        String newAccessToken = jwtService.generateAccessToken(auth);
        String newRefreshToken = jwtService.generateRefreshToken(auth);

        return new LoginResponse(newAccessToken, newRefreshToken);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<String> verifyOTP(@RequestBody OTPRequest otpRequest) {
        otpService.verifyOTP(otpRequest);
        Customer customer = customerRepository.findByPhoneNumber(otpRequest.phoneNumber()).get();
        customer.setVerified(true);
        customerRepository.save(customer);
        return ResponseEntity.ok("user verified successfully");
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<String> resendOTP(@RequestBody Map<String, String> request) {
        otpService.sendOTP(request.get("phoneNumber"));
        return ResponseEntity.ok("OTP sent successfully");
    }

    @PostMapping("/disable-user")
    public ResponseEntity<String> disableUser(@RequestBody Map<String, String> request) {
        String phoneNumber = request.get("phoneNumber");
        Customer customer = customerRepository.findByPhoneNumber(phoneNumber)
                .orElseThrow(() -> new RuntimeException("User not found"));
        customer.setEnabled(false);
        customerRepository.save(customer);
        return ResponseEntity.ok("user disabled successfully");
    }

    @PostMapping("/enable-user")
    public ResponseEntity<String> enableUser(@RequestBody Map<String, String> request) {
        String phoneNumber = request.get("phoneNumber");
        Customer customer = customerRepository.findByPhoneNumber(phoneNumber)
                .orElseThrow(() -> new RuntimeException("User not found"));
        customer.setEnabled(true);
        customerRepository.save(customer);
        return ResponseEntity.ok("user disabled successfully");
    }
}
