package com.jwt.jwttest.controller;

import com.jwt.jwttest.model.ChangePasswordRequest;
import com.jwt.jwttest.model.PasswordResetDto;
import com.jwt.jwttest.model.PasswordResetRequestDto;
import com.jwt.jwttest.service.PasswordService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/password")
public class PasswordController {

    private final PasswordService passwordService;

    public PasswordController(PasswordService passwordService) {
        this.passwordService = passwordService;
    }

    @PostMapping("/change")
    public ResponseEntity<String> change(@RequestBody ChangePasswordRequest request) {
        passwordService.changePassword(request);
        return ResponseEntity.ok("Password changed successfully");
    }

    @PostMapping("/request-reset")
    public ResponseEntity<String> requestReset(@RequestBody PasswordResetRequestDto request) {
        passwordService.requestPasswordReset(request.email());
        return ResponseEntity.ok("Password reset email sent successfully");
    }

    @PostMapping("/reset")
    public ResponseEntity<String> reset(@RequestBody PasswordResetDto request) {
        passwordService.resetPassword(request.token(), request.newPassword());
        return ResponseEntity.ok("Password reset successfully");
    }
}