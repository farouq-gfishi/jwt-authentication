package com.jwt.jwttest.controller;

import com.jwt.jwttest.entity.Customer;
import com.jwt.jwttest.repository.CustomerRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/admin/customers")
public class AdminController {

    private final CustomerRepository customerRepository;

    public AdminController(CustomerRepository customerRepository) {
        this.customerRepository = customerRepository;
    }

    @PostMapping("/disable")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> disable(@RequestBody Map<String, String> request) {
        Customer customer = customerRepository.findByEmail(request.get("email"))
                .orElseThrow(() -> new RuntimeException("User not found"));

        customer.setEnabled(false);
        customer.setTokenVersion(customer.getTokenVersion() + 1);
        customerRepository.save(customer);

        return ResponseEntity.ok("User disabled");
    }

    @PostMapping("/enable")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> enable(@RequestBody Map<String, String> request) {
        Customer customer = customerRepository.findByEmail(request.get("email"))
                .orElseThrow(() -> new RuntimeException("User not found"));

        customer.setEnabled(true);
        customerRepository.save(customer);

        return ResponseEntity.ok("User enabled");
    }
}

