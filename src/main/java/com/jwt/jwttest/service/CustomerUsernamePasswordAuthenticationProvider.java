package com.jwt.jwttest.service;

import com.jwt.jwttest.model.CustomerUserDetails;
import lombok.NonNull;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomerUsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    private final CustomerDetailsService customerDetailsService;
    private final PasswordEncoder passwordEncoder;

    public CustomerUsernamePasswordAuthenticationProvider(CustomerDetailsService customerDetailsService,
                                                          PasswordEncoder passwordEncoder) {
        this.customerDetailsService = customerDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(@NonNull Authentication authentication) throws AuthenticationException {
        String email = authentication.getName();
        String password = String.valueOf(authentication.getCredentials());
        CustomerUserDetails userDetails = loadUser(email);
        validateUser(userDetails);
        checkPassword(password, userDetails);
        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
    }

    private CustomerUserDetails loadUser(String email) {
        return (CustomerUserDetails) customerDetailsService.loadUserByUsername(email);
    }

    private void validateUser(CustomerUserDetails userDetails) {
        if (!userDetails.isEnabled()) {
            throw new BadCredentialsException("User is disabled");
        }
        if (!userDetails.isVerified()) {
            throw new BadCredentialsException("Account is not verified");
        }
    }

    private void checkPassword(String rawPassword, CustomerUserDetails userDetails) {
        if (!passwordEncoder.matches(rawPassword, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid email or password");
        }
    }

    @Override
    public boolean supports(@NonNull Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}