package com.theodore.auth.server.models;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties(prefix = "jwt.rsa")
public record RsaKeyProperties(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
}
