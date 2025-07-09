package com.theodore.auth.server.services;

import com.theodore.auth.server.entities.Role;
import com.theodore.auth.server.entities.UserAuthInfo;
import com.theodore.auth.server.entities.UserRoles;
import com.theodore.auth.server.repositories.RoleRepository;
import com.theodore.auth.server.repositories.UserAuthInfoRepository;
import com.theodore.auth.server.repositories.UserRolesRepository;
import com.theodore.racingmodel.entities.modeltypes.RoleType;
import com.theodore.racingmodel.exceptions.NotFoundException;
import com.theodore.racingmodel.exceptions.UserAlreadyExistsException;
import com.theodore.racingmodel.models.AuthUserCreatedResponseDto;
import com.theodore.racingmodel.models.CreateNewOrganizationAuthUserRequestDto;
import com.theodore.racingmodel.models.CreateNewSimpleAuthUserRequestDto;
import com.theodore.user.*;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class UserAuthServiceImpl implements UserAuthService {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserAuthServiceImpl.class);

    private final UserAuthInfoRepository userAuthInfoRepository;
    private final RoleRepository roleRepository;
    private final UserRolesRepository userRolesRepository;
    private final PasswordEncoder passwordEncoder;

    public UserAuthServiceImpl(UserAuthInfoRepository userAuthInfoRepository,
                               RoleRepository roleRepository,
                               UserRolesRepository userRolesRepository,
                               PasswordEncoder passwordEncoder) {
        this.userAuthInfoRepository = userAuthInfoRepository;
        this.roleRepository = roleRepository;
        this.userRolesRepository = userRolesRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    @Override
    public AuthUserCreatedResponse registerNewSimpleUser(CreateNewSimpleAuthUserRequest newUserRequest) {

        LOGGER.info("Registration process for user : {} ", newUserRequest.getEmail());

        if (userAuthInfoRepository.existsByEmailOrMobileNumber(newUserRequest.getEmail(), newUserRequest.getMobileNumber())) {
            throw new UserAlreadyExistsException(newUserRequest.getEmail());
        }

        UserAuthInfo newUser = new UserAuthInfo(newUserRequest.getEmail(),
                newUserRequest.getMobileNumber(),
                passwordEncoder.encode(newUserRequest.getPassword()));

        UserAuthInfo savedUser = userAuthInfoRepository.save(newUser);

        return AuthUserCreatedResponse.newBuilder()
                .setUserId(savedUser.getId())
                .build();
    }

    @Transactional
    @Override
    public AuthUserCreatedResponse registerNewOrganizationUser(CreateNewOrganizationAuthUserRequest newUserRequest) {

        LOGGER.info("Registration process for user : {} working for organization : {}", newUserRequest.getEmail(), newUserRequest.getOrganizationRegNumber());

        if (userAuthInfoRepository.existsByEmailOrMobileNumber(newUserRequest.getEmail(), newUserRequest.getMobileNumber())) {
            throw new UserAlreadyExistsException(newUserRequest.getEmail());
        }

        UserAuthInfo newUser = new UserAuthInfo(newUserRequest.getEmail(),
                newUserRequest.getMobileNumber(),
                newUserRequest.getOrganizationRegNumber(),
                passwordEncoder.encode(newUserRequest.getPassword()));

        UserAuthInfo savedUser = userAuthInfoRepository.save(newUser);

        return AuthUserCreatedResponse.newBuilder()
                .setUserId(savedUser.getId())
                .build();
    }

    @Transactional
    @Override
    public UserConfirmationResponse confirmRegistration(ConfirmUserAccountRequest request) {

        UserAuthInfo user = userAuthInfoRepository.getById(request.getUserId())
                .orElseThrow(() -> new NotFoundException("user not found"));//todo change the exception

        user.setEmailVerified(true);

        Role role = roleRepository.findByRoleTypeAndActiveTrue(RoleType.SIMPLE_USER)
                .orElseThrow(() -> new NotFoundException("role not found"));//todo change exception

        UserRoles userRole = new UserRoles(user, role);
        userRolesRepository.save(userRole);

        Set<UserRoles> userRolesSet = new HashSet<>();
        userRolesSet.add(userRole);

        user.setUserRoles(userRolesSet);

        userAuthInfoRepository.save(user);

        return UserConfirmationResponse.newBuilder().setConfirmationStatus(ConfirmationStatus.CONFIRMED).build();
    }

    @Transactional
    @Override
    public void rollbackRegistration(String userId) {
        userAuthInfoRepository.deleteById(userId);
    }

}
