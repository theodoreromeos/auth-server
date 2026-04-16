package com.theodore.auth.server.models;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "login-attempts")
public record LoginAttemptsProperties(Integer maxAttempts, Duration lockDuration) {
}
