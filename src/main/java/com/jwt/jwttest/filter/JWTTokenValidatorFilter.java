package com.jwt.jwttest.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.jwt.jwttest.constant.ApplicationConstant.*;


public class JWTTokenValidatorFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader(JWT_HEADER);
        if (header != null && header.startsWith("Bearer ")) {
            try {
                String jwt = header.substring(7);
                Environment env = getEnvironment();
                String secret = env.getProperty(JWT_SECRET_KEY, JWT_DEFAULT_VALUE);
                SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
                Claims claims = Jwts.parser()
                        .verifyWith(secretKey)
                        .build()
                        .parseSignedClaims(jwt)
                        .getPayload();
                String username = claims.get(USERNAME, String.class);
                String authorities = claims.get(AUTHORITIES, String.class);
                Authentication authentication =
                        new UsernamePasswordAuthenticationToken(
                                username,
                                null,
                                AuthorityUtils.commaSeparatedStringToAuthorityList(authorities)
                        );
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (ExpiredJwtException ex) {
                throw new BadCredentialsException("Token is expired", ex);
            } catch (Exception ex) {
                throw new BadCredentialsException("Invalid Token received", ex);
            }
        }
        filterChain.doFilter(request, response);
    }
}
