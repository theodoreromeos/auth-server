package com.theodore.auth.server.models;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt.rsa")
public record RsaKeyProperties(String privateKeyPath, String publicKeyPath, String keyId) {
}
