package com.jwt.jwttest.config;

import com.jwt.jwttest.filter.JWTTokenValidatorFilter;
import com.jwt.jwttest.properties.JWTProperties;
import com.jwt.jwttest.properties.OTPProperties;
import com.jwt.jwttest.repository.CustomerRepository;
import com.jwt.jwttest.service.JWTService;
import com.jwt.jwttest.service.OTPService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
}
