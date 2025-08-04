package com.theodore.auth.server.repositories;

import com.theodore.auth.server.entities.UserAuthInfo;
import com.theodore.racingmodel.entities.modeltypes.RoleType;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserAuthInfoRepository extends CrudRepository<UserAuthInfo, String> {

    Optional<UserAuthInfo> findByEmailIgnoreCaseAndMobileNumberIgnoreCaseAndEmailVerifiedTrue(String email, String mobileNumber);

    boolean existsByEmailOrMobileNumber(String email, String mobileNumber);

    List<UserAuthInfo> findDistinctByOrganizationRegistrationNumberAndEmailVerifiedTrueAndUserRoles_ActiveTrueAndUserRoles_Role_RoleType(
            String organizationRegistrationNumber, RoleType roleType
    );

}
