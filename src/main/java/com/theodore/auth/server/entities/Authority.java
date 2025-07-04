package com.theodore.auth.server.entities;

import com.theodore.racingmodel.entities.modeltypes.PermissionType;
import jakarta.persistence.*;

@Entity
@Table(name = "authority")
public class Authority {

    @Id
    @Column(unique = true, nullable = false)
    @Enumerated(EnumType.STRING)
    private PermissionType type;

    @Column(name = "description", nullable = false)
    @Basic
    private String description;

    @Column(name = "active", nullable = false)
    @Basic
    private Boolean active = true;

    public Authority() {
    }

    public Authority(PermissionType type) {
        this.type = type;
        this.description = type.toString();
    }

    public Authority(PermissionType type, String description) {
        this.type = type;
        this.description = description;
    }

    public PermissionType getType() {
        return type;
    }

    public void setType(PermissionType type) {
        this.type = type;
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
