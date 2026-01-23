package com.jwt.jwttest.config;

import com.jwt.jwttest.filter.JWTTokenValidatorFilter;
import com.jwt.jwttest.properties.JWTProperties;
import com.jwt.jwttest.service.JWTService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Bean
    public JWTService jwtService(JWTProperties jwtProperties) {
        return new JWTService(jwtProperties);
    }

    @Bean
    public JWTTokenValidatorFilter jwtTokenValidatorFilter(JWTService jwtService) {
        return new JWTTokenValidatorFilter(jwtService);
    }
}
