package com.theodore.auth.server.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.theodore.racingmodel.entities.AuditableUpdateEntity;
import com.theodore.racingmodel.utils.MobilityUtils;
import com.theodore.racingmodel.utils.UlidGenerated;
import jakarta.persistence.*;

import java.time.Instant;
import java.util.Set;

@Entity
@Table(name = "user_auth_info")
public class UserAuthInfo extends AuditableUpdateEntity {

    @Id
    @UlidGenerated
    @Column(length = 26, nullable = false, updatable = false)
    private String id;

    @Column(name = "email", nullable = false, length = 100)
    private String email;

    @Column(name = "mobile_number", nullable = false, length = 20)
    private String mobileNumber;

    @Column(name = "org_registration_number")
    private String organizationRegistrationNumber;

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Column(name = "password", nullable = false, length = 500)
    private String password;

    @Column(name = "last_login")
    private Instant lastLogin;

    @Column(name = "email_verified")
    private Boolean emailVerified = false;

    @Column(name = "mfa_enabled")
    private Boolean mfaEnabled = false;

    @OneToMany(mappedBy = "user", fetch = FetchType.EAGER)
    @JsonIgnore
    private Set<UserRoles> userRoles;

    public UserAuthInfo() {
    }

    public UserAuthInfo(String email, String mobileNumber, String password) {
        this.email = email;
        this.mobileNumber = mobileNumber;
        this.password = password;
    }

    public UserAuthInfo(String email, String mobileNumber, String organizationRegistrationNumber, String password) {
        this.email = email;
        this.mobileNumber = mobileNumber;
        this.organizationRegistrationNumber = organizationRegistrationNumber;
        this.password = password;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getMobileNumber() {
        return mobileNumber;
    }

    public void setMobileNumber(String mobileNumber) {
        this.mobileNumber = mobileNumber;
    }

    public String getOrganizationRegistrationNumber() {
        return organizationRegistrationNumber;
    }

    public void setOrganizationRegistrationNumber(String organizationRegistrationNumber) {
        this.organizationRegistrationNumber = organizationRegistrationNumber;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Instant getLastLogin() {
        return lastLogin;
    }

    public void setLastLogin(Instant lastLogin) {
        this.lastLogin = lastLogin;
    }

    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(Boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public Boolean getMfaEnabled() {
        return mfaEnabled;
    }

    public void setMfaEnabled(Boolean mfaEnabled) {
        this.mfaEnabled = mfaEnabled;
    }

    public Set<UserRoles> getUserRoles() {
        return userRoles;
    }

    public void setUserRoles(Set<UserRoles> userRoles) {
        this.userRoles = userRoles;
    }

    @PrePersist
    @PreUpdate
    public void normalizeEmail() {
        email = MobilityUtils.normalizeEmail(email);
    }

}