package com.theodore.auth.server.config.security;

import com.theodore.auth.server.entities.Role;
import com.theodore.auth.server.entities.UserAuthInfo;
import com.theodore.auth.server.entities.UserRoles;
import com.theodore.auth.server.repositories.RoleRepository;
import com.theodore.auth.server.repositories.UserAuthInfoRepository;
import com.theodore.auth.server.repositories.UserRolesRepository;
import com.theodore.infrastructure.common.entities.modeltypes.RoleType;
import com.theodore.infrastructure.common.exceptions.NotFoundException;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@Transactional
public class AdminAccountCreation implements ApplicationRunner {

    @Value("${admin.email}")
    private String adminEmail;

    @Value("${admin.password}")
    private String adminPassword;

    @Value("${admin.phone}")
    private String adminMobileNumber;

    private final UserAuthInfoRepository userAuthInfoRepository;
    private final UserRolesRepository userRolesRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public AdminAccountCreation(UserAuthInfoRepository userAuthInfoRepository,
                                UserRolesRepository userRolesRepository,
                                RoleRepository roleRepository,
                                PasswordEncoder passwordEncoder) {
        this.userAuthInfoRepository = userAuthInfoRepository;
        this.userRolesRepository = userRolesRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (userAuthInfoRepository.count() == 0) {
            UserAuthInfo admin = new UserAuthInfo();
            admin.setEmail(adminEmail);
            admin.setMobileNumber(adminMobileNumber);
            admin.setPassword(passwordEncoder.encode(adminPassword));
            admin.setEmailVerified(true);
            userAuthInfoRepository.save(admin);

            Role role = roleRepository.findByRoleTypeAndActiveTrue(RoleType.SYS_ADMIN)
                    .orElseThrow(() -> new NotFoundException("Role not found"));

            UserRoles userRole = new UserRoles(admin, role);
            userRolesRepository.save(userRole);
        }
    }

}
