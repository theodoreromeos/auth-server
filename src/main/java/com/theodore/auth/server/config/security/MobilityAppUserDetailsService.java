package com.theodore.auth.server.config.security;

import com.theodore.auth.server.entities.UserAuthInfo;
import com.theodore.auth.server.entities.UserRoles;
import com.theodore.auth.server.exceptions.UnverifiedAccountException;
import com.theodore.auth.server.repositories.UserAuthInfoRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MobilityAppUserDetailsService implements UserDetailsService {

    private final UserAuthInfoRepository userAuthInfoRepository;

    public MobilityAppUserDetailsService(UserAuthInfoRepository userAuthInfoRepository) {
        this.userAuthInfoRepository = userAuthInfoRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserAuthInfo user = userAuthInfoRepository.findByEmailOrMobileNumberAllIgnoreCase(username, username)
                .orElseThrow(() -> new UsernameNotFoundException("User " + username + " not found"));
        if (Boolean.FALSE.equals(user.getEmailVerified())) {
            throw new UnverifiedAccountException();
        }
        return new MobilityUserDetails(user, getGrantedAuthorities(user));
    }

    private List<GrantedAuthority> getGrantedAuthorities(UserAuthInfo user) {
        return user.getUserRoles().stream()
                .filter(UserRoles::getActive)
                .map(userRole -> (GrantedAuthority) new SimpleGrantedAuthority(userRole.getRole().getRoleType().name()))
                .toList();
    }

}
