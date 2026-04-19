package com.theodore.auth.server.models;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "csrf.cookie")
public record CsrfCookieProperties(boolean secure, String sameSite) {
}
