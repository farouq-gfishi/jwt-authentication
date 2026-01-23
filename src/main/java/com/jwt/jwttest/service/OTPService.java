package com.jwt.jwttest.service;

import com.jwt.jwttest.model.OTPRequest;
import com.jwt.jwttest.properties.OTPProperties;
import com.twilio.Twilio;
import com.twilio.rest.verify.v2.service.Verification;
import com.twilio.rest.verify.v2.service.VerificationCheck;

public class OTPService {

    private final OTPProperties otpProperties;

    public OTPService(OTPProperties otpProperties) {
        this.otpProperties = otpProperties;
    }

    public void sendOTP(String phoneNumber) {
        Twilio.init(otpProperties.getAccountSID(), otpProperties.getAuthToken());
        Verification.creator(
                        otpProperties.getPathServiceSid(),
                        phoneNumber,
                    "sms")
                .create();
    }

    public void verifyOTP(OTPRequest otpRequest) {
        Twilio.init(otpProperties.getAccountSID(), otpProperties.getAuthToken());
        VerificationCheck verificationCheck = VerificationCheck.creator(
                        otpProperties.getPathServiceSid())
                .setTo(otpRequest.phoneNumber())
                .setCode(otpRequest.otpCode())
                .create();
        if (!verificationCheck.getStatus().equals("approved")) {
            throw new RuntimeException("Invalid OTP");
        }
    }
}