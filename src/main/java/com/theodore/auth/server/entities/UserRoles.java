package com.theodore.auth.server.entities;

import com.theodore.infrastructure.common.entities.AuditableUpdateEntity;
import jakarta.persistence.*;

@Entity
@Table(
        name = "user_roles",
        uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "role_type"})
)
public class UserRoles extends AuditableUpdateEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private UserAuthInfo user;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_type", nullable = false)
    private Role role;

    @Column(name = "active")
    @Basic
    private Boolean active = true;

    public UserRoles() {
    }

    public UserRoles(UserAuthInfo user, Role role) {
        this.user = user;
        this.role = role;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public UserAuthInfo getUser() {
        return user;
    }

    public void setUser(UserAuthInfo user) {
        this.user = user;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }
}
