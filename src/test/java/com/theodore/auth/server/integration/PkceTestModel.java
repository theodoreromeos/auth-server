package com.theodore.auth.server.integration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public record PkceTestModel(String verifier, String challenge) {

    public static PkceTestModel createPkceTestModel() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);

        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        byte[] hash = sha256(verifier.getBytes(StandardCharsets.US_ASCII));
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

        return new PkceTestModel(verifier, challenge);
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

}
