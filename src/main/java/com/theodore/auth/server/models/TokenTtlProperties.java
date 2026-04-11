package com.theodore.auth.server.models;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "token.ttl")
public record TokenTtlProperties(Duration pkceAccess,
                                 Duration pkceRefresh,
                                 Duration clientCredentialsAccess) {

}
