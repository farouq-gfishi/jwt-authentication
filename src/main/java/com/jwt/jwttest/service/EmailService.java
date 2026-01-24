package com.jwt.jwttest.service;

import com.jwt.jwttest.exception.custom.EmailServiceException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;
    private final String from;

    public EmailService(JavaMailSender mailSender,
                        @Value("${spring.mail.username}") String from) {
        this.mailSender = mailSender;
        this.from = from;
    }

    public void sendVerificationEmail(String email, String verificationToken) {
        log.info("Sending verification email to: {}", email);
        String subject = "Email Verification";
        String path = "/auth/verify-email";
        String message = "Click the button below to verify your email address:";
        sendEmail(email, verificationToken, subject, path, message);
    }

    public void sendForgotPasswordEmail(String email, String resetToken) {
        log.info("Sending password reset email to: {}", email);
        String subject = "Password Reset Request";
        String path = "/password/reset-password";
        String message = "Click the button below to reset your password:";
        sendEmail(email, resetToken, subject, path, message);
    }

    private void sendEmail(String email, String token, String subject, String path, String message) {
        try {
            String actionUrl = ServletUriComponentsBuilder.fromCurrentContextPath()
                    .path(path)
                    .queryParam("token", token)
                    .toUriString();

            String content = """
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border-radius: 8px; background-color: #f9f9f9; text-align: center;">
                            <h2 style="color: #333;">%s</h2>
                            <p style="font-size: 16px; color: #555;">%s</p>
                            <a href="%s" style="display: inline-block; margin: 20px 0; padding: 10px 20px; font-size: 16px; color: #fff; background-color: #007bff; text-decoration: none; border-radius: 5px;">Proceed</a>
                            <p style="font-size: 14px; color: #777;">Or copy and paste this link into your browser:</p>
                            <p style="font-size: 14px; color: #007bff;">%s</p>
                            <p style="font-size: 12px; color: #aaa;">This is an automated message. Please do not reply.</p>
                        </div>
                    """.formatted(subject, message, actionUrl, actionUrl);

            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);

            helper.setTo(email);
            helper.setSubject(subject);
            helper.setFrom(from);
            helper.setText(content, true);
            mailSender.send(mimeMessage);
            log.info("Email sent successfully to: {}", email);
        } catch (Exception e) {
            log.error("Failed to send email to: {}", email, e);
            throw new EmailServiceException("Failed to send email", e);
        }
    }
}