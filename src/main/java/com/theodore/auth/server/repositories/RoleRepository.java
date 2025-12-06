package com.theodore.auth.server.repositories;

import com.theodore.auth.server.entities.Role;
import com.theodore.infrastructure.common.entities.modeltypes.RoleType;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface RoleRepository extends CrudRepository<Role, RoleType> {

    Optional<Role> findByRoleTypeAndActiveTrue(RoleType roleType);

}