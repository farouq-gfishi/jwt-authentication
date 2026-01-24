package com.jwt.jwttest.service;

import com.jwt.jwttest.model.CustomerUserDetails;
import com.jwt.jwttest.model.TokenType;
import com.jwt.jwttest.properties.JWTProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Objects;
import java.util.stream.Collectors;

import static com.jwt.jwttest.constant.ApplicationConstant.*;
import static com.jwt.jwttest.model.TokenType.ACCESS;
import static com.jwt.jwttest.model.TokenType.REFRESH;
import static io.jsonwebtoken.Jwts.SIG.HS256;

public class JWTService {

    private final JWTProperties jwtProperties;

    public JWTService(JWTProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public String generateAccessToken(Authentication auth) {
        return buildToken(auth, ACCESS, null, jwtProperties.getAccessTokenExpiration());
    }

    public String generateAccessToken(Authentication auth, Integer tokenVersion) {
        return buildToken(auth, ACCESS, tokenVersion, jwtProperties.getAccessTokenExpiration());
    }

    public String generateRefreshToken(Authentication auth) {
        return buildToken(auth, REFRESH, null, jwtProperties.getRefreshTokenExpiration());
    }

    public String generateRefreshToken(Authentication auth, Integer tokenVersion) {
        return buildToken(auth, REFRESH, tokenVersion, jwtProperties.getRefreshTokenExpiration());
    }

    public String generateEmailToken(String email) {
        return Jwts.builder()
                .subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtProperties.getAccessTokenExpiration()))
                .signWith(getSecretKey(), HS256)
                .compact();
    }

    public Claims validateAccessToken(String accessToken) {
        return validateAndExtractClaims(accessToken, ACCESS);
    }

    public Claims validateRefreshToken(String refreshToken) {
        return validateAndExtractClaims(refreshToken, REFRESH);
    }

    public Claims validateAndExtractClaims(String token, TokenType expectedTokenType) {
        Claims claims = parseToken(token);
        String tokenType = claims.get(TOKEN_TYPE, String.class);
        if (!expectedTokenType.name().equals(tokenType)) {
            throw new BadCredentialsException(
                    String.format("Invalid token type. Expected %s but got %s",
                            expectedTokenType.name(),
                            tokenType != null ? tokenType : "null")
            );
        }
        return claims;
    }

    public String extractEmail(String token) {
        Claims claims = parseToken(token);
        return claims.getSubject();
    }

    public boolean isTokenExpired(String token) {
        Claims claims = parseToken(token);
        return claims.getExpiration().before(new Date());
    }

    private String buildToken(Authentication auth, TokenType type, Integer tokenVersion, long expirationMillis) {
        String authorities = auth.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        return Jwts.builder()
                .subject("Test Application")
                .claim(USERNAME, auth.getName())
                .claim(TOKEN_TYPE, type.name())
                .claim("tv", getTokenVersion(tokenVersion, auth))
                .claim(AUTHORITIES, authorities)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMillis))
                .signWith(getSecretKey(), HS256)
                .compact();
    }

    private Integer getTokenVersion(Integer tokenVersion, Authentication auth) {
        if(tokenVersion != null) return tokenVersion;
        CustomerUserDetails user = (CustomerUserDetails) auth.getPrincipal();
        return Objects.requireNonNull(user).getTokenVersion();
    }

    private Claims parseToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new BadCredentialsException("Token has expired", e);
        } catch (Exception e) {
            throw new BadCredentialsException("Invalid token", e);
        }
    }

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }
}
