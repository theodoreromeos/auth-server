package com.theodore.auth.server.entities;

import com.theodore.racingmodel.entities.modeltypes.RoleType;
import jakarta.persistence.*;

@Entity
@Table(name = "role")
public class Role {

    @Id
    @Column(unique = true, nullable = false)
    @Enumerated(EnumType.STRING)
    private RoleType roleType;

    @Column(name = "description", nullable = false)
    @Basic
    private String description;

    @Column(name = "active", nullable = false)
    @Basic
    private Boolean active = true;

    public Role() {
    }

    public Role(RoleType roleType) {
        this.roleType = roleType;
        this.description = roleType.toString();
    }

    public Role(RoleType roleType, String description) {
        this.roleType = roleType;
        this.description = description;
    }

    public RoleType getRoleType() {
        return roleType;
    }

    public void setRoleType(RoleType roleType) {
        this.roleType = roleType;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

}