package com.jwt.jwttest.security.service;

import com.jwt.jwttest.domain.entity.Customer;
import com.jwt.jwttest.domain.model.CustomerUserDetails;
import com.jwt.jwttest.repository.CustomerRepository;
import lombok.NonNull;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Set;
import java.util.stream.Collectors;

public class CustomerDetailsService implements UserDetailsService {

    private final CustomerRepository customerRepository;

    public CustomerDetailsService(CustomerRepository customerRepository) {
        this.customerRepository = customerRepository;
    }

    @Override
    public @NonNull UserDetails loadUserByUsername(@NonNull String email) {
        Customer customer = customerRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        Set<SimpleGrantedAuthority> authorities = customer.getAuthorities().stream()
                .map(auth -> new SimpleGrantedAuthority(auth.getName()))
                .collect(Collectors.toSet());
        return new CustomerUserDetails(
                customer.getEmail(),
                customer.getPassword(),
                Boolean.TRUE.equals(customer.getEnabled()),
                Boolean.TRUE.equals(customer.getVerified()),
                customer.getTokenVersion(),
                authorities
        );
    }
}