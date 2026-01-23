package com.jwt.jwttest.service;

import com.jwt.jwttest.model.CustomerUserDetails;
import lombok.NonNull;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Objects;

public record CustomerUsernamePasswordAuthenticationProvider(CustomerDetailsService customerDetailsService,
                                                             PasswordEncoder passwordEncoder) implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String phoneNumber = authentication.getName();
        String password = Objects.requireNonNull(authentication.getCredentials()).toString();
        CustomerUserDetails userDetails =
                (CustomerUserDetails) customerDetailsService.loadUserByUsername(phoneNumber);
        if (!userDetails.isVerified()) {
            throw new BadCredentialsException("Account is not verified");
        }
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid phone number or password");
        }
        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
    }

    @Override
    public boolean supports(@NonNull Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
