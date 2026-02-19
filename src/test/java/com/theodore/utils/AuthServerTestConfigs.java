package com.theodore.utils;

import com.theodore.auth.server.TestDataHelper;
import com.theodore.auth.server.repositories.RoleRepository;
import com.theodore.auth.server.repositories.UserAuthInfoRepository;
import com.theodore.auth.server.repositories.UserRolesRepository;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

@TestConfiguration
public class AuthServerTestConfigs {

    @Bean
    public TestDataHelper testDataFeeder(JdbcTemplate jdbcTemplate,
                                         UserAuthInfoRepository userAuthInfoRepository,
                                         RoleRepository roleRepository,
                                         UserRolesRepository userRolesRepository,
                                         PasswordEncoder passwordEncoder) {
        return new TestDataHelper(jdbcTemplate,
                userAuthInfoRepository,
                roleRepository,
                userRolesRepository,
                passwordEncoder);
    }

}
