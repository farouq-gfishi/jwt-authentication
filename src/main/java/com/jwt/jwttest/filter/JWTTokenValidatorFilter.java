package com.jwt.jwttest.filter;

import com.jwt.jwttest.entity.Customer;
import com.jwt.jwttest.repository.CustomerRepository;
import com.jwt.jwttest.service.JWTService;
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
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader(JWT_HEADER);

        if (header != null && header.startsWith("Bearer ")) {
            try {
                String jwt = header.substring(7);
                Claims claims = jwtService.validateAccessToken(jwt);
                Integer tokenVersionInToken = claims.get("tv", Integer.class);
                String email = claims.get(USERNAME, String.class);
                String authorities = claims.get(AUTHORITIES, String.class);
                Customer customer = customerRepository.findByEmail(email)
                        .orElseThrow(() -> new BadCredentialsException("User not found"));
                if (!customer.getEnabled()) {
                    throw new BadCredentialsException("User is disabled");
                }
                if (!tokenVersionInToken.equals(customer.getTokenVersion())) {
                    throw new BadCredentialsException("Token revoked");
                }
                Authentication authentication =
                        new UsernamePasswordAuthenticationToken(
                                email,
                                null,
                                AuthorityUtils.commaSeparatedStringToAuthorityList(authorities)
                        );
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (BadCredentialsException ex) {
                throw ex;
            } catch (Exception ex) {
                throw new BadCredentialsException("Invalid Token received", ex);
            }
        }
        filterChain.doFilter(request, response);
    }
}