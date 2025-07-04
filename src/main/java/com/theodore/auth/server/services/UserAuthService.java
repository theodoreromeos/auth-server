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
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class UserAuthService {

    private final UserAuthInfoRepository userAuthInfoRepository;
    private final RoleRepository roleRepository;
    private final UserRolesRepository userRolesRepository;
    private final PasswordEncoder passwordEncoder;

    public UserAuthService(UserAuthInfoRepository userAuthInfoRepository,
                           RoleRepository roleRepository,
                           UserRolesRepository userRolesRepository,
                           PasswordEncoder passwordEncoder) {
        this.userAuthInfoRepository = userAuthInfoRepository;
        this.roleRepository = roleRepository;
        this.userRolesRepository = userRolesRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public AuthUserCreatedResponseDto registerNewSimpleUser(CreateNewSimpleAuthUserRequestDto newUserRequestDto) {

        if (userAuthInfoRepository.existsByEmailOrMobileNumber(newUserRequestDto.email(), newUserRequestDto.mobileNumber())) {
            throw new UserAlreadyExistsException(newUserRequestDto.email());
        }

        UserAuthInfo newUser = new UserAuthInfo(newUserRequestDto.email(),
                newUserRequestDto.mobileNumber(),
                passwordEncoder.encode(newUserRequestDto.password()));

        UserAuthInfo savedUser = userAuthInfoRepository.save(newUser);

        return new AuthUserCreatedResponseDto(savedUser.getId());
    }

    @Transactional
    public AuthUserCreatedResponseDto registerNewOrganizationUser(CreateNewOrganizationAuthUserRequestDto userRequestDto) {

        if (userAuthInfoRepository.existsByEmailOrMobileNumber(userRequestDto.email(), userRequestDto.mobileNumber())) {
            throw new UserAlreadyExistsException(userRequestDto.email());
        }


        UserAuthInfo newUser = new UserAuthInfo(userRequestDto.email(),
                userRequestDto.mobileNumber(),
                userRequestDto.organizationRegNumber(),
                passwordEncoder.encode(userRequestDto.password()));

        UserAuthInfo savedUser = userAuthInfoRepository.save(newUser);

        return new AuthUserCreatedResponseDto(savedUser.getId());
    }

    @Transactional
    public void confirmRegistration(String userId) {
        UserAuthInfo user = userAuthInfoRepository.getById(userId)
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
    }

    @Transactional
    public void rollbackRegistration(String userId) {
        userAuthInfoRepository.deleteById(userId);
    }

}
