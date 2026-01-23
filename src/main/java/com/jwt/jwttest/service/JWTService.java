package com.jwt.jwttest.service;

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
import java.util.stream.Collectors;

import static com.jwt.jwttest.constant.ApplicationConstant.AUTHORITIES;
import static com.jwt.jwttest.constant.ApplicationConstant.TOKEN_TYPE;
import static io.jsonwebtoken.Jwts.SIG.HS256;

public class JWTService {

    private final JWTProperties jwtProperties;

    public JWTService(JWTProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Authentication auth) {
        String authorities = auth.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .subject(auth.getName())
                .claim(AUTHORITIES, authorities)
                .claim(TOKEN_TYPE, "ACCESS")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtProperties.getAccessTokenExpiration()))
                .signWith(getSecretKey(), HS256)
                .compact();
    }

    public String generateRefreshToken(Authentication auth) {
        return Jwts.builder()
                .claim(TOKEN_TYPE, "REFRESH")
                .subject(auth.getName())
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

    public String validateRefreshTokenAndGetUsername(String refreshToken) {
        Claims claims = validateAndExtractClaims(refreshToken, "REFRESH");
        return extractUsername(claims);
    }

    public String extractUsername(Claims claims) {
        return claims.getSubject();
    }

    public Claims validateAccessToken(String accessToken) {
        return validateAndExtractClaims(accessToken, "ACCESS");
    }
}
