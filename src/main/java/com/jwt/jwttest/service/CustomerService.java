package com.jwt.jwttest.service;

import com.jwt.jwttest.entity.Customer;
import com.jwt.jwttest.exception.UserNotFoundException;
import com.jwt.jwttest.repository.CustomerRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
public class CustomerService {

    private final CustomerRepository customerRepository;

    public CustomerService(CustomerRepository customerRepository) {
        this.customerRepository = customerRepository;
    }

    public Customer findByEmail(String email) {
        return customerRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException(email));
    }

    @Transactional
    public void disableCustomer(String email) {
        log.info("Disabling customer with email: {}", email);
        Customer customer = findByEmail(email);
        customer.setEnabled(false);
        customer.setTokenVersion(customer.getTokenVersion() + 1);
        customerRepository.save(customer);
        log.info("Customer disabled successfully: {}", email);
    }

    @Transactional
    public void enableCustomer(String email) {
        log.info("Enabling customer with email: {}", email);
        Customer customer = findByEmail(email);
        customer.setEnabled(true);
        customerRepository.save(customer);
        log.info("Customer enabled successfully: {}", email);
    }

    @Transactional
    public void incrementTokenVersion(Customer customer) {
        customer.setTokenVersion(customer.getTokenVersion() + 1);
        customerRepository.save(customer);
    }

    @Transactional
    public void save(Customer customer) {
        customerRepository.save(customer);
    }
}