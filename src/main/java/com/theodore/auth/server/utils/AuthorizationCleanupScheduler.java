package com.theodore.auth.server.utils;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationCleanupScheduler {

    private final JdbcTemplate jdbcTemplate;

    public AuthorizationCleanupScheduler(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Scheduled(cron = "0 0 */6 * * *")
    public void cleanupExpiredAuthorizations() {
        jdbcTemplate.update("""
            DELETE FROM oauth2_authorization
            WHERE (access_token_expires_at IS NOT NULL AND access_token_expires_at < NOW())
            AND (refresh_token_expires_at IS NULL OR refresh_token_expires_at < NOW())
            AND (authorization_code_expires_at IS NULL OR authorization_code_expires_at < NOW())
        """);
    }
}