package com.jwt.jwttest.config;

import com.jwt.jwttest.exception.CustomAccessDeniedHandler;
import com.jwt.jwttest.exception.CustomBasicAuthenticationEntryPoint;
import com.jwt.jwttest.filter.JWTTokenValidatorFilter;
import com.jwt.jwttest.repository.CustomerRepository;
import com.jwt.jwttest.service.CustomerDetailsService;
import com.jwt.jwttest.service.CustomerUsernamePasswordAuthenticationProvider;
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

import java.util.Collections;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) {
        http.sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(STATELESS))
                .cors(corsConfig -> corsConfig.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                    config.setAllowedMethods(Collections.singletonList("*"));
                    config.setAllowCredentials(true);
                    config.setAllowedHeaders(Collections.singletonList("*"));
                    config.setExposedHeaders(List.of("Authorization"));
                    config.setMaxAge(3600L);
                    return config;
                }))
                .csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore(new JWTTokenValidatorFilter(), ExceptionTranslationFilter.class)
//                .redirectToHttps(withDefaults())
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/error", "/register", "/invalid-session", "/getToken", "/notSecure", "/refreshToken").permitAll()
                        .anyRequest().authenticated());
        http.formLogin(withDefaults());
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        http.exceptionHandling(ex -> ex.accessDeniedHandler(new CustomAccessDeniedHandler()));
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
    public AuthenticationProvider authenticationProvider(CustomerDetailsService customerDetailsService,
                                                         PasswordEncoder passwordEncoder) {
        return new CustomerUsernamePasswordAuthenticationProvider(customerDetailsService, passwordEncoder);
    }

    @Bean
    public AuthenticationManager authenticationManager(CustomerDetailsService customerDetailsService,
                                                       PasswordEncoder passwordEncoder) {
        CustomerUsernamePasswordAuthenticationProvider authenticationProvider =
                new CustomerUsernamePasswordAuthenticationProvider(customerDetailsService, passwordEncoder);
        ProviderManager providerManager = new ProviderManager(authenticationProvider);
        providerManager.setEraseCredentialsAfterAuthentication(false);
        return providerManager;
    }
}
