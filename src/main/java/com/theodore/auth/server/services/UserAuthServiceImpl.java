package com.theodore.auth.server.services;

import com.theodore.auth.server.entities.Role;
import com.theodore.auth.server.entities.UserAuthInfo;
import com.theodore.auth.server.entities.UserRoles;
import com.theodore.auth.server.exceptions.RoleAlreadyAssignedException;
import com.theodore.auth.server.repositories.RoleRepository;
import com.theodore.auth.server.repositories.UserAuthInfoRepository;
import com.theodore.auth.server.repositories.UserRolesRepository;
import com.theodore.infrastructure.common.entities.enums.RoleType;
import com.theodore.infrastructure.common.exceptions.CommonErrorMessages;
import com.theodore.infrastructure.common.exceptions.NotFoundException;
import com.theodore.infrastructure.common.exceptions.RollbackProcessingException;
import com.theodore.infrastructure.common.exceptions.UserAlreadyExistsException;
import com.theodore.infrastructure.common.utils.MobilityUtils;
import com.theodore.queue.common.authserver.RolesRollbackEventDto;
import com.theodore.user.*;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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
        String email = MobilityUtils.normalizeEmail(newUserRequest.getEmail());

        LOGGER.info("Registration process for user : {} ", email);

        if (userAuthInfoRepository.existsByEmailOrMobileNumber(email, newUserRequest.getMobileNumber())) {
            throw new UserAlreadyExistsException(email);
        }

        UserAuthInfo newUser = new UserAuthInfo(email,
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
        String email = MobilityUtils.normalizeEmail(newUserRequest.getEmail());

        LOGGER.info("Registration process for user : {} working for organization : {}", email, newUserRequest.getOrganizationRegNumber());

        if (userAuthInfoRepository.existsByEmailOrMobileNumber(email, newUserRequest.getMobileNumber())) {
            throw new UserAlreadyExistsException(email);
        }

        UserAuthInfo newUser = new UserAuthInfo(email,
                newUserRequest.getMobileNumber(),
                newUserRequest.getOrganizationRegNumber(),
                passwordEncoder.encode(newUserRequest.getPassword()));

        UserAuthInfo savedUser = userAuthInfoRepository.save(newUser);

        RoleType roleType = RoleType.valueOf(newUserRequest.getRole());

        Role role = roleRepository.findByRoleTypeAndActiveTrue(roleType)
                .orElseThrow(() -> new NotFoundException(CommonErrorMessages.ROLE_NOT_FOUND));

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
                .orElseThrow(() -> new NotFoundException(CommonErrorMessages.USER_NOT_FOUND));

        user.setEmailVerified(true);

        if (CollectionUtils.isEmpty(user.getUserRoles())) {
            Role role = roleRepository.findByRoleTypeAndActiveTrue(RoleType.SIMPLE_USER)
                    .orElseThrow(() -> new NotFoundException(CommonErrorMessages.ROLE_NOT_FOUND));

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
                .orElseThrow(() -> new NotFoundException(CommonErrorMessages.USER_NOT_FOUND));

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
        var user = userAuthInfoRepository.findById(userId).orElseThrow(() -> new NotFoundException(CommonErrorMessages.USER_NOT_FOUND));
        if (!CollectionUtils.isEmpty(user.getUserRoles())) {
            userRolesRepository.deleteAll(user.getUserRoles());
        }
        userAuthInfoRepository.delete(user);
    }

    @Transactional
    @Override
    public void manageAuthUserAccount(ManageAuthUserAccountRequest manageUserAccountRequest) {
        UserAuthInfo user = userAuthInfoRepository.findByIdAndEmailIgnoreCaseOrMobileNumber(
                manageUserAccountRequest.getUserId(),
                manageUserAccountRequest.getOldEmail(),
                manageUserAccountRequest.getMobileNumber()
        ).orElseThrow(() -> new NotFoundException(CommonErrorMessages.USER_NOT_FOUND));
        if (!passwordEncoder.matches(manageUserAccountRequest.getOldPassword(), user.getPassword())) {
            throw new BadCredentialsException("Passwords do not match");
        }
        user.setMobileNumber(manageUserAccountRequest.getMobileNumber());
        user.setPassword(passwordEncoder.encode(manageUserAccountRequest.getNewPassword()));
        user.setEmail(MobilityUtils.normalizeEmail(manageUserAccountRequest.getNewEmail()));
        userAuthInfoRepository.save(user);
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

    @Transactional
    @Override
    public void addUserRole(AddRoleRequest request) {
        var user = userAuthInfoRepository.findById(request.getUserId()).orElseThrow(() -> new NotFoundException(CommonErrorMessages.USER_NOT_FOUND));
        RoleType roleType = RoleType.fromString(request.getRole());
        checkValidityOfAddingRoleToUser(user, roleType);
        UserRoles newUserRole = new UserRoles();
        newUserRole.setUser(user);
        newUserRole.setActive(true);
        Role role = roleRepository.findByRoleTypeAndActiveTrue(roleType).orElseThrow(() -> new NotFoundException(CommonErrorMessages.ROLE_NOT_FOUND));
        newUserRole.setRole(role);
        userRolesRepository.save(newUserRole);
    }

    @Transactional
    @Override
    public void removeUserRoles(RolesRollbackEventDto request) {

        var allUserRoles = userRolesRepository.findByUser_Id(request.userId());

        if(CollectionUtils.isEmpty(allUserRoles)){
            throw new NotFoundException(CommonErrorMessages.USER_NOT_FOUND);
        }
        List<UserRoles> rolesToRemove = allUserRoles.stream()
                .filter(ur -> request.rolesToBeRemoved().contains(ur.getRole().getRoleType()))
                .toList();

        if (rolesToRemove.isEmpty()) {
            return;
        }
        validateRoleRemoval(request.userId(), allUserRoles.size(), rolesToRemove.size());

        userRolesRepository.deleteAllInBatch(rolesToRemove);
    }

    private void checkValidityOfAddingRoleToUser(UserAuthInfo user, RoleType roleType) {
        if (user.getUserRoles().stream().anyMatch(userRole -> userRole.getRole().getRoleType().equals(roleType))) {
            throw new RoleAlreadyAssignedException();
        }
        if (user.getUserRoles().isEmpty()) {
            throw new NotFoundException("User roles not found");
        }
    }

    private void validateRoleRemoval(String userId, int currentRoleCount, int rolesToRemoveCount) {
        if (rolesToRemoveCount >= currentRoleCount) {
            throw new RollbackProcessingException("Cannot remove all roles from user with id: " + userId);
        }
    }

}
