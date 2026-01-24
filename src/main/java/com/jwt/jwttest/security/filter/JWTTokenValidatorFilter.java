package com.jwt.jwttest.security.filter;

import com.jwt.jwttest.domain.entity.Customer;
import com.jwt.jwttest.repository.CustomerRepository;
import com.jwt.jwttest.security.service.JWTService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.jwt.jwttest.constant.ApplicationConstant.*;

public class JWTTokenValidatorFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JWTService jwtService;
    private final CustomerRepository customerRepository;

    public JWTTokenValidatorFilter(JWTService jwtService,
                                   CustomerRepository customerRepository) {
        this.jwtService = jwtService;
        this.customerRepository = customerRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader(JWT_HEADER);
        if (isBearerToken(header)) {
            try {
                authenticate(header);
            } catch (BadCredentialsException ex) {
                throw ex;
            } catch (Exception ex) {
                throw new BadCredentialsException("Invalid Token received", ex);
            }
        }
        filterChain.doFilter(request, response);
    }

    private boolean isBearerToken(String header) {
        return header != null && header.startsWith(BEARER_PREFIX);
    }

    private void authenticate(String header) {
        String token = extractToken(header);
        Claims claims = jwtService.validateAccessToken(token);
        String email = getRequiredClaim(claims, USERNAME, String.class);
        Integer tokenVersion = getRequiredClaim(claims, "tv", Integer.class);
        String authorities = getRequiredClaim(claims, AUTHORITIES, String.class);
        Customer customer = loadCustomer(email);
        validateCustomer(customer, tokenVersion);
        setSecurityContext(email, authorities);
    }

    private String extractToken(String header) {
        return header.substring(BEARER_PREFIX.length());
    }

    private <T> T getRequiredClaim(Claims claims, String name, Class<T> type) {
        T value = claims.get(name, type);
        if (value == null) {
            throw new BadCredentialsException("Missing claim: " + name);
        }
        return value;
    }

    private Customer loadCustomer(String email) {
        return customerRepository.findByEmail(email)
                .orElseThrow(() -> new BadCredentialsException("User not found"));
    }

    private void validateCustomer(Customer customer, Integer tokenVersionInToken) {
        if (!Boolean.TRUE.equals(customer.getEnabled())) {
            throw new BadCredentialsException("User is disabled");
        }
        if (!tokenVersionInToken.equals(customer.getTokenVersion())) {
            throw new BadCredentialsException("Token revoked");
        }
    }

    private void setSecurityContext(String email, String authorities) {
        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        email,
                        null,
                        AuthorityUtils.commaSeparatedStringToAuthorityList(authorities)
                );
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
