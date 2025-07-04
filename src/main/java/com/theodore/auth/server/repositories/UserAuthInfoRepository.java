package com.theodore.auth.server.repositories;

import com.theodore.auth.server.entities.UserAuthInfo;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserAuthInfoRepository extends CrudRepository<UserAuthInfo, Long> {

    Optional<UserAuthInfo> findByEmailIgnoreCaseAndMobileNumberIgnoreCaseAndEmailVerifiedTrue(String email, String mobileNumber);

    boolean existsByEmailOrMobileNumber(String email, String mobileNumber);

    Optional<UserAuthInfo> getById(String id);

    void deleteById(String id);
}
