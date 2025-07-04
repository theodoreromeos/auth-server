package com.theodore.auth.server.config;

import com.theodore.auth.server.entities.UserAuthInfo;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

public class MobilityUserDetails extends User {

    private final String email;
    private final String organizationRegNumber;
    private final List<String> roles;

    public MobilityUserDetails(UserAuthInfo user, List<String> roles, Collection<? extends GrantedAuthority> authorities) {
        super(user.getEmail(), user.getPassword(), authorities);
        this.email = user.getEmail();
        this.roles = roles;
        this.organizationRegNumber = user.getOrganizationRegistrationNumber();
    }

    public String getEmail() {
        return email;
    }

    public String getOrganizationRegNumber() {
        return organizationRegNumber;
    }

    public List<String> getRoles() {
        return roles;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof MobilityUserDetails that)) return false;
        if (!super.equals(o)) return false;
        return Objects.equals(getEmail(), that.getEmail()) && Objects.equals(getOrganizationRegNumber(), that.getOrganizationRegNumber()) && Objects.equals(getRoles(), that.getRoles());
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), getEmail(), getOrganizationRegNumber(), getRoles());
    }
}
