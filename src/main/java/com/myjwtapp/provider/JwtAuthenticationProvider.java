package com.myjwtapp.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static com.myjwtapp.service.JwtUtil.extractUserDetailsFromToken;
import static com.myjwtapp.service.JwtUtil.validateToken;

public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String token = (String) authentication.getCredentials();

        if (validateToken(token)) {
            UserDetails userDetails = extractUserDetailsFromToken(token);
            return new UsernamePasswordAuthenticationToken(userDetails,"", userDetails.getAuthorities());
        }

        throw new UsernameNotFoundException("Invalid token");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
