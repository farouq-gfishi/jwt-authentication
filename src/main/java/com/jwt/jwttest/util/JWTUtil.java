package com.jwt.jwttest.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

import static io.jsonwebtoken.Jwts.SIG.HS256;

public class JWTUtil {

    public static final long ACCESS_TOKEN_EXPIRATION = 2 * 60 * 1000;      // 2 minutes
    public static final long REFRESH_TOKEN_EXPIRATION = 5 * 60 * 1000;     // 5 minutes
    public static final String SECRET = "3cnNbOFmGFFMzqgq54bYgKQuAzvkbd2fNXtmFl7GSBd";

    private static SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }

    public static String generateAccessToken(Authentication auth) {
        String authorities = auth.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .subject(auth.getName())
                .claim("authorities", authorities)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION))
                .signWith(getSecretKey(), HS256)
                .compact();
    }

    public static String generateRefreshToken(Authentication auth) {
        return Jwts.builder()
                .subject(auth.getName())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION))
                .signWith(getSecretKey(), HS256)
                .compact();
    }
}
