package com.theodore.auth.server.config.security;

import com.theodore.auth.server.entities.UserAuthInfo;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Objects;

public class MobilityUserDetails extends User {

    private final String email;
    private final String organizationRegNumber;

    public MobilityUserDetails(UserAuthInfo user, Collection<? extends GrantedAuthority> roles) {
        super(user.getEmail(), user.getPassword(), roles);
        this.email = user.getEmail();
        this.organizationRegNumber = user.getOrganizationRegistrationNumber();
    }

    public MobilityUserDetails(String email, String password, boolean enabled,
                               boolean accountNonExpired, boolean credentialsNonExpired,
                               boolean accountNonLocked, String organizationRegNumber,
                               Collection<? extends GrantedAuthority> authorities) {
        super(email, password, enabled, accountNonExpired,
                credentialsNonExpired, accountNonLocked, authorities);
        this.email = email;
        this.organizationRegNumber = organizationRegNumber;
    }

    public String getEmail() {
        return email;
    }

    public String getOrganizationRegNumber() {
        return organizationRegNumber;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof MobilityUserDetails that)) return false;
        if (!super.equals(o)) return false;
        return Objects.equals(getEmail(), that.getEmail()) && Objects.equals(getOrganizationRegNumber(), that.getOrganizationRegNumber());
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), getEmail(), getOrganizationRegNumber());
    }
}
