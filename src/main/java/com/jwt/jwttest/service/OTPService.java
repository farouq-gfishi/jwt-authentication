package com.jwt.jwttest.service;

import com.jwt.jwttest.exception.InvalidOTPException;
import com.jwt.jwttest.model.OTPRequest;
import com.jwt.jwttest.properties.OTPProperties;
import com.twilio.Twilio;
import com.twilio.rest.verify.v2.service.Verification;
import com.twilio.rest.verify.v2.service.VerificationCheck;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class OTPService {

    private final OTPProperties otpProperties;

    public OTPService(OTPProperties otpProperties) {
        this.otpProperties = otpProperties;
    }

    @PostConstruct
    public void init() {
        Twilio.init(otpProperties.getAccountSID(), otpProperties.getAuthToken());
    }

    public void sendOTP(String phoneNumber) {
        log.info("Sending OTP to phone number: {}", phoneNumber);
        try {
            Verification.creator(
                            otpProperties.getPathServiceSid(),
                            phoneNumber,
                            "sms")
                    .create();
            log.info("OTP sent successfully to: {}", phoneNumber);
        } catch (Exception e) {
            log.error("Failed to send OTP to: {}", phoneNumber, e);
            throw new InvalidOTPException();
        }
    }

    public void verifyOTP(OTPRequest otpRequest) {
        log.info("Verifying OTP for phone number: {}", otpRequest.phoneNumber());
        try {
            VerificationCheck verificationCheck = VerificationCheck.creator(
                            otpProperties.getPathServiceSid())
                    .setTo(otpRequest.phoneNumber())
                    .setCode(otpRequest.otpCode())
                    .create();

            if (!"approved".equals(verificationCheck.getStatus())) {
                log.warn("Invalid OTP provided for phone number: {}", otpRequest.phoneNumber());
                throw new InvalidOTPException();
            }
            log.info("OTP verified successfully for: {}", otpRequest.phoneNumber());
        } catch (InvalidOTPException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to verify OTP for: {}", otpRequest.phoneNumber(), e);
            throw new InvalidOTPException();
        }
    }
}