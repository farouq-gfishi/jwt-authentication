package com.jwt.jwttest.model;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Set;

public class CustomerUserDetails extends User {

    private final boolean verified;

    public CustomerUserDetails(String username,
                               String password,
                               boolean verified,
                               Set<SimpleGrantedAuthority> authorities) {
        super(username, password, authorities);
        this.verified = verified;
    }

    public boolean isVerified() {
        return verified;
    }
}
