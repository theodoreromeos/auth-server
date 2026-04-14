package com.theodore.auth.server.services;

import com.theodore.auth.server.entities.UserAuthInfo;
import com.theodore.auth.server.repositories.UserAuthInfoRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

@Service
public class LoginAttemptServiceImpl implements LoginAttemptService {

    private static final int MAX_ATTEMPTS = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(2);

    private final UserAuthInfoRepository userAuthInfoRepository;

    public LoginAttemptServiceImpl(UserAuthInfoRepository userAuthInfoRepository) {
        this.userAuthInfoRepository = userAuthInfoRepository;
    }

    @Transactional
    @Override
    public void recordFailure(String username) {
        userAuthInfoRepository.findByEmailOrMobileNumberAllIgnoreCase(username, username)
                .ifPresent(user -> {
                    int attempts = user.getFailedLoginAttempts() + 1;
                    user.setFailedLoginAttempts(attempts);
                    if (attempts >= MAX_ATTEMPTS) {
                        user.setLockExpiry(Instant.now().plus(LOCKOUT_DURATION));
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
