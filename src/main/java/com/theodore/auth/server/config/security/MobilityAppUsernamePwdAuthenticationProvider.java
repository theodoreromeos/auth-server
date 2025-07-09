package com.theodore.auth.server.config.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class MobilityAppUsernamePwdAuthenticationProvider implements AuthenticationProvider {

    private final MobilityAppUserDetailsService mobilityAppUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    public MobilityAppUsernamePwdAuthenticationProvider(MobilityAppUserDetailsService mobilityAppUserDetailsService,
                                                     PasswordEncoder passwordEncoder) {
        this.mobilityAppUserDetailsService = mobilityAppUserDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        UserDetails userDetails = mobilityAppUserDetailsService.loadUserByUsername(username);
        if (passwordEncoder.matches(password, userDetails.getPassword())) {
            return new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
        } else {
            throw new BadCredentialsException("INVALID CREDENTIALS");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
