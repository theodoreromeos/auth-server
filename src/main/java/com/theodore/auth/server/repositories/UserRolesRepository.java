package com.theodore.auth.server.repositories;

import com.theodore.auth.server.entities.UserRoles;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface UserRolesRepository extends JpaRepository<UserRoles, Long> {

    List<UserRoles> findByUser_Id(String id);

}