package com.jwt.jwttest.model;

import lombok.Getter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Set;

@Getter
public class CustomerUserDetails extends User {

    private final boolean enabled;
    private final boolean verified;
    private final Integer tokenVersion;

    public CustomerUserDetails(String username,
                               String password,
                               boolean enabled,
                               boolean verified,
                               Integer tokenVersion,
                               Set<SimpleGrantedAuthority> authorities) {
        super(username, password, authorities);
        this.enabled = enabled;
        this.verified = verified;
        this.tokenVersion = tokenVersion;
    }

}
