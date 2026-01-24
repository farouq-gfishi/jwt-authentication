package com.jwt.jwttest.config;

import com.jwt.jwttest.exception.handler.CustomAccessDeniedHandler;
import com.jwt.jwttest.exception.handler.CustomBasicAuthenticationEntryPoint;
import com.jwt.jwttest.security.filter.JWTTokenValidatorFilter;
import com.jwt.jwttest.repository.CustomerRepository;
import com.jwt.jwttest.security.service.CustomerDetailsService;
import com.jwt.jwttest.security.provider.CustomerUsernamePasswordAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private static final List<String> PUBLIC_ENDPOINTS = List.of(
            // === Auth ===
            "/auth/login",
            "/auth/refresh-token",

            // === Registration & Verification ===
            "/auth/register",
            "/auth/verify-email",
            "/auth/verify-otp",
            "/auth/resend-otp",

            // === Password Management ===
            "/password/request-reset",
            "/password/reset",

            // === System / Errors ===
            "/error",
            "/invalid-session",
            "/notSecure"
    );


    private static final List<String> ALLOWED_ORIGINS = List.of("http://localhost:4200");

    private final JWTTokenValidatorFilter jwtTokenValidatorFilter;

    public SecurityConfig(JWTTokenValidatorFilter jwtTokenValidatorFilter) {
        this.jwtTokenValidatorFilter = jwtTokenValidatorFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) {
        http
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                .cors(cors -> cors.configurationSource(request -> corsConfiguration()))
                .csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore(jwtTokenValidatorFilter, ExceptionTranslationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_ENDPOINTS.toArray(String[]::new)).permitAll()
                        .anyRequest().authenticated()
                )
                .httpBasic(basic -> basic.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()))
                .exceptionHandling(ex -> ex.accessDeniedHandler(new CustomAccessDeniedHandler()));
        return http.build();
    }

    @Bean
    public CustomerDetailsService customerDetailsService(CustomerRepository customerRepository) {
        return new CustomerDetailsService(customerRepository);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(
            CustomerDetailsService customerDetailsService,
            PasswordEncoder passwordEncoder
    ) {
        return new CustomerUsernamePasswordAuthenticationProvider(
                customerDetailsService,
                passwordEncoder
        );
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationProvider authenticationProvider) {
        ProviderManager providerManager = new ProviderManager(authenticationProvider);
        providerManager.setEraseCredentialsAfterAuthentication(false);
        return providerManager;
    }

    private CorsConfiguration corsConfiguration() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(ALLOWED_ORIGINS);
        config.setAllowedMethods(List.of("*"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setExposedHeaders(List.of("Authorization"));
        config.setMaxAge(3600L);
        return config;
    }
}
