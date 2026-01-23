package com.jwt.jwttest.properties;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Getter
@Configuration
public class OTPProperties {


    @Value("${otp.account-sid}")
    private String accountSID;

    @Value("${otp.auth-token}")
    private String authToken;

    @Value("${otp.path-service-sid}")
    private String pathServiceSid;
}
