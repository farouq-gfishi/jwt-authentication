package com.jwt.jwttest.service;

import com.jwt.jwttest.entity.Customer;
import com.jwt.jwttest.model.CustomerUserDetails;
import com.jwt.jwttest.repository.CustomerRepository;
import lombok.NonNull;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Set;
import java.util.stream.Collectors;

public record CustomerDetailsService(CustomerRepository userRepository) implements UserDetailsService {

    @Override
    public @NonNull UserDetails loadUserByUsername(@NonNull String username) {
        Customer customer = userRepository.findByPhoneNumber(username).orElseThrow(() -> new
                UsernameNotFoundException("User details not found for the user: " + username));
        Set<SimpleGrantedAuthority> authorities = customer.getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getName()))
                .collect(Collectors.toSet());
        return new CustomerUserDetails(
                customer.getPhoneNumber(),
                customer.getPassword(),
                Boolean.TRUE.equals(customer.getEnabled()),
                Boolean.TRUE.equals(customer.getVerified()),
                authorities
        );
    }
}