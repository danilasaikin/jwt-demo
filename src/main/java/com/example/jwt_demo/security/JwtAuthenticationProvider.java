package com.example.jwt_demo.security;


import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;



public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token = (String) authentication.getCredentials();

        try {
            UserDetails userDetails = JwtUtil.extractUserDetailsFromToken(token);
            if (JwtUtil.validateToken(token, userDetails)) {
                return new JwtAuthenticationToken(userDetails, token, userDetails.getAuthorities());
            }
        } catch (Exception e) {
            throw new AuthenticationException("JWT Token is not valid", e) {};
        }

        throw new AuthenticationException("JWT Token is not valid") {};
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

