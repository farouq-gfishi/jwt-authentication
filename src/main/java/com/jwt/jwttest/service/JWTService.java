package com.jwt.jwttest.service;

import com.jwt.jwttest.model.CustomerUserDetails;
import com.jwt.jwttest.properties.JWTProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.antlr.v4.runtime.misc.Pair;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

import static com.jwt.jwttest.constant.ApplicationConstant.*;
import static io.jsonwebtoken.Jwts.SIG.HS256;

public class JWTService {

    private final JWTProperties jwtProperties;

    public JWTService(JWTProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Authentication auth, Integer tokenVersion) {
        String authorities = auth.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        return Jwts.builder()
                .subject("Test Application")
                .claim(USERNAME, auth.getName())
                .claim(TOKEN_TYPE, "ACCESS")
                .claim("tv", tokenVersion)
                .claim(AUTHORITIES, authorities)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtProperties.getAccessTokenExpiration()))
                .signWith(getSecretKey(), HS256)
                .compact();
    }

    public String generateAccessToken(Authentication auth) {
        String authorities = auth.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        CustomerUserDetails user = (CustomerUserDetails) auth.getPrincipal();
        return Jwts.builder()
                .subject("Test Application")
                .claim(USERNAME, auth.getName())
                .claim(TOKEN_TYPE, "ACCESS")
                .claim("tv", user.getTokenVersion())
                .claim(AUTHORITIES, authorities)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtProperties.getAccessTokenExpiration()))
                .signWith(getSecretKey(), HS256)
                .compact();
    }

    public String generateRefreshToken(Authentication auth, Integer tokenVersion) {
        return Jwts.builder()
                .subject("Test Application")
                .claim(USERNAME, auth.getName())
                .claim(TOKEN_TYPE, "REFRESH")
                .claim("tv", tokenVersion)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtProperties.getRefreshTokenExpiration()))
                .signWith(getSecretKey(), HS256)
                .compact();
    }

    public String generateRefreshToken(Authentication auth) {
        CustomerUserDetails user = (CustomerUserDetails) auth.getPrincipal();
        return Jwts.builder()
                .subject("Test Application")
                .claim(USERNAME, auth.getName())
                .claim(TOKEN_TYPE, "REFRESH")
                .claim("tv", user.getTokenVersion())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtProperties.getRefreshTokenExpiration()))
                .signWith(getSecretKey(), HS256)
                .compact();
    }

    public Claims validateAndExtractClaims(String token, String expectedTokenType) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            String tokenType = claims.get(TOKEN_TYPE, String.class);
            if (!expectedTokenType.equals(tokenType)) {
                throw new BadCredentialsException(
                        String.format("Invalid token type. Expected %s but got %s",
                                expectedTokenType,
                                tokenType != null ? tokenType : "null")
                );
            }
            return claims;
        } catch (ExpiredJwtException ex) {
            throw new BadCredentialsException("Token has expired", ex);
        } catch (BadCredentialsException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new BadCredentialsException("Invalid token", ex);
        }
    }

    public Pair<String, Integer> validateRefreshTokenAndGetUsername(String refreshToken) {
        Claims claims = validateAndExtractClaims(refreshToken, "REFRESH");
        return extractUsername(claims);
    }

    public Pair<String, Integer> extractUsername(Claims claims) {
        String username = claims.get(USERNAME, String.class);
        Integer tokenVersionInToken = claims.get("tv", Integer.class);
        return new Pair<>(username, tokenVersionInToken);
    }

    public Claims validateAccessToken(String accessToken) {
        return validateAndExtractClaims(accessToken, "ACCESS");
    }
}
