package com.jwt.jwttest.config;

import com.jwt.jwttest.filter.JWTTokenValidatorFilter;
import com.jwt.jwttest.properties.JWTProperties;
import com.jwt.jwttest.properties.OTPProperties;
import com.jwt.jwttest.repository.CustomerRepository;
import com.jwt.jwttest.service.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AppConfig {

    @Bean
    public JWTService jwtService(JWTProperties jwtProperties) {
        return new JWTService(jwtProperties);
    }

    @Bean
    public JWTTokenValidatorFilter jwtTokenValidatorFilter(JWTService jwtService,
                                                           CustomerRepository customerRepository) {
        return new JWTTokenValidatorFilter(jwtService, customerRepository);
    }

    @Bean
    public OTPService otpService(OTPProperties otpProperties) {
        return new OTPService(otpProperties);
    }

    @Bean
    public EmailService emailService(JavaMailSender mailSender,
                                     @Value("${spring.mail.username}") String from) {
        return new EmailService(mailSender, from);
    }

    @Bean
    public CustomerService customerService(CustomerRepository customerRepository) {
        return new CustomerService(customerRepository);
    }

    @Bean
    public AuthService authService(AuthenticationManager authenticationManager,
                                   JWTService jwtService,
                                   CustomerService customerService) {
        return new AuthService(authenticationManager, jwtService, customerService);
    }

    @Bean
    public PasswordService passwordService(CustomerService customerService,
                                           PasswordEncoder passwordEncoder,
                                           JWTService jwtService,
                                           EmailService emailService) {
        return new PasswordService(customerService, passwordEncoder, jwtService, emailService);
    }

    @Bean
    public RegistrationService registrationService(CustomerRepository customerRepository,
                                                   PasswordEncoder passwordEncoder,
                                                   JWTService jwtService,
                                                   EmailService emailService) {
        return new RegistrationService(customerRepository, passwordEncoder, jwtService, emailService);
    }

}
