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
import com.theodore.user.*;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

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
    public AuthUserIdResponse registerNewSimpleUser(CreateNewSimpleAuthUserRequest newUserRequest) {

        LOGGER.info("Registration process for user : {} ", newUserRequest.getEmail());

        if (userAuthInfoRepository.existsByEmailOrMobileNumber(newUserRequest.getEmail(), newUserRequest.getMobileNumber())) {
            throw new UserAlreadyExistsException(newUserRequest.getEmail());
        }

        UserAuthInfo newUser = new UserAuthInfo(newUserRequest.getEmail(),
                newUserRequest.getMobileNumber(),
                passwordEncoder.encode(newUserRequest.getPassword()));

        UserAuthInfo savedUser = userAuthInfoRepository.save(newUser);

        return AuthUserIdResponse.newBuilder()
                .setUserId(savedUser.getId())
                .build();
    }

    @Transactional
    @Override
    public AuthUserIdResponse registerNewOrganizationUser(CreateNewOrganizationAuthUserRequest newUserRequest) {

        LOGGER.info("Registration process for user : {} working for organization : {}", newUserRequest.getEmail(), newUserRequest.getOrganizationRegNumber());

        if (userAuthInfoRepository.existsByEmailOrMobileNumber(newUserRequest.getEmail(), newUserRequest.getMobileNumber())) {
            throw new UserAlreadyExistsException(newUserRequest.getEmail());
        }

        UserAuthInfo newUser = new UserAuthInfo(newUserRequest.getEmail(),
                newUserRequest.getMobileNumber(),
                newUserRequest.getOrganizationRegNumber(),
                passwordEncoder.encode(newUserRequest.getPassword()));

        UserAuthInfo savedUser = userAuthInfoRepository.save(newUser);

        RoleType roleType = RoleType.valueOf(newUserRequest.getRole());

        Role role = roleRepository.findByRoleTypeAndActiveTrue(roleType)
                .orElseThrow(() -> new NotFoundException("role not found"));//todo change exception

        UserRoles userRole = new UserRoles(savedUser, role);
        userRolesRepository.save(userRole);

        return AuthUserIdResponse.newBuilder()
                .setUserId(savedUser.getId())
                .build();
    }

    @Transactional
    @Override
    public UserConfirmationResponse confirmRegistration(ConfirmUserAccountRequest accountConfirmationRequest) {

        UserAuthInfo user = userAuthInfoRepository.findById(accountConfirmationRequest.getUserId())
                .orElseThrow(() -> new NotFoundException("user not found"));//todo change the exception

        user.setEmailVerified(true);

        if (CollectionUtils.isEmpty(user.getUserRoles())) {
            Role role = roleRepository.findByRoleTypeAndActiveTrue(RoleType.SIMPLE_USER)
                    .orElseThrow(() -> new NotFoundException("role not found"));//todo change exception

            UserRoles userRole = new UserRoles(user, role);
            userRolesRepository.save(userRole);
            Set<UserRoles> userRolesSet = new HashSet<>();
            userRolesSet.add(userRole);
            user.setUserRoles(userRolesSet);
        }

        userAuthInfoRepository.save(user);

        return UserConfirmationResponse.newBuilder().setConfirmationStatus(ConfirmationStatus.CONFIRMED).build();
    }

    @Transactional
    @Override
    public UserConfirmationResponse confirmOrganizationAdminRegistration(ConfirmAdminAccountRequest request) {

        UserAuthInfo user = userAuthInfoRepository.findById(request.getUserId())
                .orElseThrow(() -> new NotFoundException("user not found"));//todo change the exception

        LOGGER.info("OLD PASSWORD: {} ", request.getOldPassword());
        LOGGER.info("current password: {} ", user.getPassword());

        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Old password is incorrect");
        }

        user.setEmailVerified(true);
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userAuthInfoRepository.save(user);

        return UserConfirmationResponse.newBuilder().setConfirmationStatus(ConfirmationStatus.CONFIRMED).build();
    }

    @Transactional
    @Override
    public void rollbackRegistration(String userId) {
        var user = userAuthInfoRepository.findById(userId).orElseThrow(() -> new NotFoundException("user not found"));
        if (!CollectionUtils.isEmpty(user.getUserRoles())) {
            userRolesRepository.deleteAll(user.getUserRoles());
        }
        userAuthInfoRepository.delete(user);
    }

    @Transactional
    @Override
    public AuthUserIdResponse manageAuthUserAccount(ManageAuthUserAccountRequest manageUserAccountRequest) {
        UserAuthInfo user = userAuthInfoRepository.findByEmailIgnoreCaseAndMobileNumberIgnoreCaseAndEmailVerifiedTrue(manageUserAccountRequest.getOldEmail(),
                manageUserAccountRequest.getMobileNumber()).orElseThrow(() -> new NotFoundException("user not found"));
        if (!passwordEncoder.matches(manageUserAccountRequest.getOldPassword(), user.getPassword())) {
            throw new RuntimeException("Passwords do not match");//todo
        }
        user.setMobileNumber(manageUserAccountRequest.getMobileNumber());
        user.setPassword(passwordEncoder.encode(manageUserAccountRequest.getNewPassword()));
        user.setEmail(manageUserAccountRequest.getNewEmail());
        userAuthInfoRepository.save(user);

        return AuthUserIdResponse.newBuilder()
                .setUserId(user.getId())
                .build();
    }

    @Override
    public OrgAdminIdAndEmailResponse getOrganizationAdminInfo(String orgRegistrationNumber) {
        var orgAdmins = userAuthInfoRepository
                .findDistinctByOrganizationRegistrationNumberAndEmailVerifiedTrueAndUserRoles_ActiveTrueAndUserRoles_Role_RoleType(
                        orgRegistrationNumber, RoleType.ORGANIZATION_ADMIN
                );
        var adminIdAndEmailList = orgAdmins.stream()
                .map(orgAdmin -> OrganizationAdminUserIdAndEmail.newBuilder()
                        .setAdminId(orgAdmin.getId())
                        .setAdminEmail(orgAdmin.getEmail())
                        .build())
                .toList();

        return OrgAdminIdAndEmailResponse.newBuilder().addAllOrganizationAdminInfo(adminIdAndEmailList).build();
    }
}
