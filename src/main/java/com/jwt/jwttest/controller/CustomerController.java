package com.jwt.jwttest.controller;

import com.jwt.jwttest.entity.Authority;
import com.jwt.jwttest.entity.Customer;
import com.jwt.jwttest.model.ChangePasswordRequest;
import com.jwt.jwttest.model.LoginRequest;
import com.jwt.jwttest.model.LoginResponse;
import com.jwt.jwttest.model.OTPRequest;
import com.jwt.jwttest.repository.CustomerRepository;
import com.jwt.jwttest.service.EmailService;
import com.jwt.jwttest.service.JWTService;
import com.jwt.jwttest.service.OTPService;
import io.jsonwebtoken.Claims;
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
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static com.jwt.jwttest.constant.ApplicationConstant.USERNAME;

@RestController
public class CustomerController {

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;
    private final OTPService otpService;
    private final EmailService emailService;

    public CustomerController(CustomerRepository customerRepository,
                              PasswordEncoder passwordEncoder,
                              AuthenticationManager authenticationManager,
                              JWTService jwtService,
                              OTPService otpService,
                              EmailService emailService) {
        this.customerRepository = customerRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.otpService = otpService;
        this.emailService = emailService;
    }

    @PostMapping("/register")
    @Transactional
    public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
        Optional<Customer> user = customerRepository.findByEmail(customer.getEmail());
        if (user.isPresent()) {
            if (user.get().getVerified()) {
                return new ResponseEntity<>("User Already exist and Verified.", HttpStatus.BAD_REQUEST);
            }
            String verificationToken = jwtService.generateEmailToken(user.get().getEmail());
            user.get().setVerificationToken(verificationToken);
            customerRepository.save(user.get());
            emailService.sendVerificationEmail(user.get().getEmail(), verificationToken);
            return new ResponseEntity<>("Verification Email resent. Check your inbox",HttpStatus.OK);
        }
        customer.setPassword(passwordEncoder.encode(customer.getPassword()));
        Authority authority = new Authority();
        authority.setName("ROLE_USER");
        authority.setCustomer(customer);
        customer.setAuthorities(Set.of(authority));
        String verificationToken =jwtService.generateEmailToken(customer.getEmail());
        customer.setVerificationToken(verificationToken);
        customerRepository.save(customer);
        emailService.sendVerificationEmail(customer.getEmail(), verificationToken);
        return ResponseEntity.status(HttpStatus.CREATED).body("created successfully");
    }

    @GetMapping("/verify")
    public ResponseEntity verifyEmail(@RequestParam("token") String token) {
        String emailString = jwtService.extractEmail(token);
        Optional<Customer> user = customerRepository.findByEmail(emailString);
        if (user.isEmpty() || user.get().getVerificationToken() == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Token Expired!");
        }

        if (jwtService.isTokenExpired(token) || !user.get().getVerificationToken().equals(token)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Token Expired!");
        }
        user.get().setVerificationToken(null);
        user.get().setVerified(true);
        customerRepository.save(user.get());

        return ResponseEntity.status(HttpStatus.CREATED).body("Email successfully verified!");
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String accessToken = jwtService.generateAccessToken(authentication);
        String refreshToken = jwtService.generateRefreshToken(authentication);
        return new LoginResponse(accessToken, refreshToken);
    }

    @PostMapping("/refresh-token")
    public LoginResponse refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        Claims claims = jwtService.validateRefreshToken(refreshToken);
        String username = claims.get(USERNAME, String.class);
        Integer tokenVersionInToken = claims.get("tv", Integer.class);
        Customer customer = customerRepository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        if (!customer.getEnabled()) {
            throw new BadCredentialsException("User is disabled");
        }
        if (!tokenVersionInToken.equals(customer.getTokenVersion())) {
            throw new BadCredentialsException("Token revoked");
        }
        List<GrantedAuthority> authorities = customer.getAuthorities()
                .stream()
                .map(a -> new SimpleGrantedAuthority(a.getName()))
                .collect(Collectors.toList());
        Authentication auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
        String newAccessToken = jwtService.generateAccessToken(auth, tokenVersionInToken);
        String newRefreshToken = jwtService.generateRefreshToken(auth, tokenVersionInToken);

        return new LoginResponse(newAccessToken, newRefreshToken);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<String> verifyOTP(@RequestBody OTPRequest otpRequest) {
        otpService.verifyOTP(otpRequest);
        Customer customer = customerRepository.findByEmail(otpRequest.phoneNumber()).get();
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
        String email = request.get("email");
        Customer customer = customerRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        customer.setEnabled(false);
        customer.setTokenVersion(customer.getTokenVersion() + 1);
        customerRepository.save(customer);
        return ResponseEntity.ok("user disabled successfully");
    }

    @PostMapping("/enable-user")
    public ResponseEntity<String> enableUser(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        Customer customer = customerRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        customer.setEnabled(true);
        customerRepository.save(customer);
        return ResponseEntity.ok("user disabled successfully");
    }

    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(@RequestBody ChangePasswordRequest request) {
        Customer customer = customerRepository.findByEmail(request.email())
                .orElseThrow(() -> new RuntimeException("User not found"));
        if (!passwordEncoder.matches(request.oldPassword(), customer.getPassword())) {
            return ResponseEntity.badRequest().body("old password is incorrect");
        }
        customer.setPassword(passwordEncoder.encode(request.newPassword()));
        customer.setTokenVersion(customer.getTokenVersion() + 1);
        customerRepository.save(customer);
        return ResponseEntity.ok("password changed successfully");
    }

    @PostMapping("/request-reset-password")
    public ResponseEntity<String> requestResetPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        Customer customer = customerRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        String resetToken = jwtService.generateEmailToken(customer.getEmail());
        customer.setVerificationToken(resetToken);
        customerRepository.save(customer);
        emailService.sendForgotPasswordEmail(customer.getEmail(), resetToken);
        return ResponseEntity.ok("Password reset email sent");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String newPassword = request.get("newPassword");
        String email = jwtService.extractEmail(token);
        Customer customer = customerRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        if (jwtService.isTokenExpired(token) || !token.equals(customer.getVerificationToken())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid or expired token");
        }
        customer.setPassword(passwordEncoder.encode(newPassword));
        customer.setVerificationToken(null);
        customer.setTokenVersion(customer.getTokenVersion() + 1);
        customerRepository.save(customer);
        return ResponseEntity.ok("Password reset successfully");
    }

}
