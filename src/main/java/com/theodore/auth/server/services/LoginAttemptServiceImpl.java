package com.theodore.auth.server.services;

import com.theodore.auth.server.entities.UserAuthInfo;
import com.theodore.auth.server.models.LoginAttemptsProperties;
import com.theodore.auth.server.repositories.UserAuthInfoRepository;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@EnableConfigurationProperties(LoginAttemptsProperties.class)
public class LoginAttemptServiceImpl implements LoginAttemptService {

    private final UserAuthInfoRepository userAuthInfoRepository;
    private final LoginAttemptsProperties loginAttemptsProperties;

    public LoginAttemptServiceImpl(UserAuthInfoRepository userAuthInfoRepository,
                                   LoginAttemptsProperties loginAttemptsProperties) {
        this.userAuthInfoRepository = userAuthInfoRepository;
        this.loginAttemptsProperties = loginAttemptsProperties;
    }

    @Transactional
    @Override
    public void recordFailure(String username) {
        userAuthInfoRepository.findByEmailOrMobileNumberAllIgnoreCase(username, username)
                .ifPresent(user -> {
                    Integer attempts = user.getFailedLoginAttempts() + 1;
                    user.setFailedLoginAttempts(attempts);
                    if (attempts >= loginAttemptsProperties.maxAttempts()) {
                        user.setLockExpiry(Instant.now().plus(loginAttemptsProperties.lockDuration()));
                    }
                    userAuthInfoRepository.save(user);
                });
    }

    @Transactional
    @Override
    public void recordSuccess(String username, String ipAddress) {
        userAuthInfoRepository.findByEmailOrMobileNumberAllIgnoreCase(username, username)
                .ifPresent(user -> {
                    user.setLastLogin(Instant.now());
                    user.setLastLoginIp(ipAddress);
                    user.setFailedLoginAttempts(0);
                    user.setLockExpiry(null);
                    userAuthInfoRepository.save(user);
                });
    }

    @Override
    public boolean isLocked(UserAuthInfo user) {
        Instant lockExpires = user.getLockExpiry();
        return lockExpires != null && lockExpires.isAfter(Instant.now());
    }

}
