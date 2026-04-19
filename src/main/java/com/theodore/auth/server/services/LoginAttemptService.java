package com.theodore.auth.server.services;

import com.theodore.auth.server.entities.UserAuthInfo;
import org.springframework.stereotype.Service;

@Service
public interface LoginAttemptService {

    void recordFailure(String username);

    void recordSuccess(String username, String ipAddress);

    boolean isLocked(UserAuthInfo user);

}
