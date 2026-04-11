package com.theodore.auth.server.repositories;

import com.theodore.auth.server.entities.UserAuthInfo;
import com.theodore.infrastructure.common.entities.enums.RoleType;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserAuthInfoRepository extends CrudRepository<UserAuthInfo, String> {

    Optional<UserAuthInfo> findByEmailOrMobileNumberAllIgnoreCase(String email, String mobileNumber);

    boolean existsByEmailOrMobileNumber(String email, String mobileNumber);

    List<UserAuthInfo> findDistinctByOrganizationRegistrationNumberAndEmailVerifiedTrueAndUserRoles_ActiveTrueAndUserRoles_Role_RoleType(
            String organizationRegistrationNumber, RoleType roleType
    );

    @Query("select u from UserAuthInfo u where u.id = ?1 and (upper(u.email) = upper(?2) or u.mobileNumber = ?3)")
    Optional<UserAuthInfo> findByIdAndEmailIgnoreCaseOrMobileNumber(String id, String email, String mobileNumber);

}
