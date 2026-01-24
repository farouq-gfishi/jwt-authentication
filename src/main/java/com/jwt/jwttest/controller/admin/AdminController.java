package com.jwt.jwttest.controller.admin;

import com.jwt.jwttest.domain.dto.request.CustomerEnableDisableDto;
import com.jwt.jwttest.service.CustomerService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final CustomerService customerService;

    public AdminController(CustomerService customerService) {
        this.customerService = customerService;
    }

    @PostMapping("/disable-user")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> disable(@RequestBody CustomerEnableDisableDto request) {
        customerService.disableCustomer(request.email());
        return ResponseEntity.ok("User disabled successfully");
    }

    @PostMapping("/enable-user")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> enable(@RequestBody CustomerEnableDisableDto request) {
        customerService.enableCustomer(request.email());
        return ResponseEntity.ok("User enabled successfully");
    }
}