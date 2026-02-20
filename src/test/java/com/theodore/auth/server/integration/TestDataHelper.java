package com.theodore.auth.server.integration;

import com.theodore.auth.server.entities.Role;
import com.theodore.auth.server.entities.UserAuthInfo;
import com.theodore.auth.server.entities.UserRoles;
import com.theodore.auth.server.repositories.RoleRepository;
import com.theodore.auth.server.repositories.UserAuthInfoRepository;
import com.theodore.auth.server.repositories.UserRolesRepository;
import com.theodore.infrastructure.common.entities.modeltypes.RoleType;
import com.theodore.auth.server.utils.TestData;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

public class TestDataHelper {

    private final JdbcTemplate jdbcTemplate;
    private final UserAuthInfoRepository userAuthInfoRepository;
    private final RoleRepository roleRepository;
    private final UserRolesRepository userRolesRepository;
    private final PasswordEncoder passwordEncoder;

    public TestDataHelper(JdbcTemplate jdbcTemplate,
                          UserAuthInfoRepository userAuthInfoRepository,
                          RoleRepository roleRepository,
                          UserRolesRepository userRolesRepository,
                          PasswordEncoder passwordEncoder) {
        this.jdbcTemplate = jdbcTemplate;
        this.userAuthInfoRepository = userAuthInfoRepository;
        this.roleRepository = roleRepository;
        this.userRolesRepository = userRolesRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public void initAuthData() {
        jdbcTemplate.execute("DELETE FROM oauth2_authorization_consent");
        jdbcTemplate.execute("DELETE FROM oauth2_authorization");
        ensureTestUsersExist();
    }

    private void ensureTestUsersExist() {
        if (userAuthInfoRepository.findByEmailOrMobileNumberAllIgnoreCase(TestData.SIMPLE_USER_TEST_EMAIL, TestData.SIMPLE_USER_TEST_PHONE).isEmpty()) {
            var simpleUser = createVerifiedUser(TestData.SIMPLE_USER_TEST_EMAIL, TestData.SIMPLE_USER_TEST_PHONE, null);
            var simpleUserRole = new UserRoles(simpleUser, getRole(RoleType.SIMPLE_USER));
            userRolesRepository.save(simpleUserRole);
        }
        if (userAuthInfoRepository.findByEmailOrMobileNumberAllIgnoreCase(TestData.ORG_USER_TEST_EMAIL, TestData.ORG_USER_TEST_PHONE).isEmpty()) {
            var orgUser = createVerifiedUser(TestData.ORG_USER_TEST_EMAIL, TestData.ORG_USER_TEST_PHONE, TestData.TEST_ORG_REG_NUMBER);
            var orgUserRole = new UserRoles(orgUser, getRole(RoleType.MECHANIC));
            userRolesRepository.save(orgUserRole);
        }
    }

    private Role getRole(RoleType roleType) {

        return roleRepository.findByRoleTypeAndActiveTrue(roleType)
                .orElseGet(() -> {
                    var newRole = new Role();
                    newRole.setRoleType(roleType);
                    newRole.setActive(true);
                    return roleRepository.save(newRole);
                });
    }

    private UserAuthInfo createVerifiedUser(String email, String phoneNumber, String orgRegNumber) {
        var user = new UserAuthInfo(email, phoneNumber, passwordEncoder.encode(TestData.TEST_PASSWORD));
        user.setEmailVerified(true);
        user.setOrganizationRegistrationNumber(orgRegNumber);

        return userAuthInfoRepository.save(user);
    }

}
