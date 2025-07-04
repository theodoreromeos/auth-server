package com.theodore.auth.server.repositories;

import com.theodore.auth.server.entities.UserRoles;
import org.springframework.data.repository.CrudRepository;

public interface UserRolesRepository extends CrudRepository<UserRoles, Long> {
}