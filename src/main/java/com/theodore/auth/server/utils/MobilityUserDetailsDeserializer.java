package com.theodore.auth.server.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theodore.auth.server.config.security.MobilityUserDetails;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class MobilityUserDetailsDeserializer extends JsonDeserializer<MobilityUserDetails> {

    private static final String EMAIL = "email";
    private static final String PASSWORD = "password";
    private static final String ORG_REG_NUMBER = "organizationRegNumber";

    private static final String ENABLED = "enabled";
    private static final String ACCOUNT_NON_EXPIRED = "accountNonExpired";
    private static final String CREDENTIALS_NON_EXPIRED = "credentialsNonExpired";
    private static final String ACCOUNT_NON_LOCKED = "accountNonLocked";

    private static final String AUTHORITIES = "authorities";
    private static final String AUTHORITY = "authority";

    @Override
    public MobilityUserDetails deserialize(JsonParser parser, DeserializationContext ctxt)
            throws IOException {
        ObjectMapper mapper = (ObjectMapper) parser.getCodec();
        JsonNode root = mapper.readTree(parser);

        var email = root.path(EMAIL).asText();

        var password = extractText(root, PASSWORD, "");
        var organizationRegNumber = extractText(root, ORG_REG_NUMBER, null);

        var enabled = extractBoolean(root, ENABLED);
        var accountNonExpired = extractBoolean(root, ACCOUNT_NON_EXPIRED);
        var credentialsNonExpired = extractBoolean(root, CREDENTIALS_NON_EXPIRED);
        var accountNonLocked = extractBoolean(root, ACCOUNT_NON_LOCKED);

        var authorities = parseAuthorities(root.path(AUTHORITIES));

        return new MobilityUserDetails(
                email,
                password,
                enabled,
                accountNonExpired,
                credentialsNonExpired,
                accountNonLocked,
                organizationRegNumber,
                authorities
        );
    }

    private static String extractText(JsonNode node, String field, String defaultValue) {
        var value = node.path(field);
        return value.isMissingNode() || value.isNull() ? defaultValue : value.asText();
    }

    private static boolean extractBoolean(JsonNode node, String field) {
        var value = node.path(field);
        return value.isMissingNode() || value.isNull() || value.asBoolean(true);
    }

    private static List<GrantedAuthority> parseAuthorities(JsonNode authoritiesNode) {
        if (authoritiesNode == null || !authoritiesNode.isArray()) {
            return List.of();
        }

        JsonNode arrayToIterate = authoritiesNode;
        if (authoritiesNode.size() == 2
                && authoritiesNode.get(0).isTextual()
                && authoritiesNode.get(1).isArray()) {
            arrayToIterate = authoritiesNode.get(1);
        }

        var authorities = new ArrayList<GrantedAuthority>();
        for (var authNode : arrayToIterate) {
            var authority = authNode.path(AUTHORITY).asText(null);
            if (authority != null && !authority.isBlank()) {
                authorities.add(new SimpleGrantedAuthority(authority));
            }
        }
        return authorities;
    }

}