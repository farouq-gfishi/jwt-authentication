package com.jwt.jwttest.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/secure")
    @PreAuthorize("hasRole('USER')")
    public String secure() {
        return "secure";
    }

    @GetMapping("/notSecure")
    public String notSecure() {
        return "notSecure";
    }

    @PostMapping("/postSecure")
    public String postSecure() {
        return "postSecure";
    }
}
