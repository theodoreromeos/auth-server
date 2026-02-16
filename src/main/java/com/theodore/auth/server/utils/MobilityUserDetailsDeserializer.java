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

    private static final String ORG_REG_NUMBER = "orgRegNumber";
    private static final String PASSWORD = "password";

    @Override
    public MobilityUserDetails deserialize(JsonParser parser, DeserializationContext ctxt)
            throws IOException {
        ObjectMapper mapper = (ObjectMapper) parser.getCodec();
        JsonNode root = mapper.readTree(parser);

        // Spring Security User
        String password = root.has(PASSWORD) && !root.get(PASSWORD).isNull()
                ? root.get(PASSWORD).asText() : "";
        boolean enabled = root.has("enabled") ? root.get("enabled").asBoolean() : true;
        boolean accountNonExpired = root.has("accountNonExpired")
                ? root.get("accountNonExpired").asBoolean() : true;
        boolean credentialsNonExpired = root.has("credentialsNonExpired")
                ? root.get("credentialsNonExpired").asBoolean() : true;
        boolean accountNonLocked = root.has("accountNonLocked")
                ? root.get("accountNonLocked").asBoolean() : true;

        String email = root.get("email").asText();
        String organizationRegNumber = root.has(ORG_REG_NUMBER)
                && !root.get(ORG_REG_NUMBER).isNull()
                ? root.get(ORG_REG_NUMBER).asText() : null;

        // Authorities
        List<GrantedAuthority> authorities = new ArrayList<>();
        JsonNode authoritiesNode = root.get("authorities");
        if (authoritiesNode != null && authoritiesNode.isArray()) {
            if (authoritiesNode.size() == 2
                    && authoritiesNode.get(0).isTextual()
                    && authoritiesNode.get(1).isArray()) {
                authoritiesNode = authoritiesNode.get(1);
            }
            for (JsonNode authNode : authoritiesNode) {
                if (authNode.isObject() && authNode.has("authority")) {
                    String authority = authNode.get("authority").asText();
                    if (authority != null && !authority.isBlank()) {
                        authorities.add(new SimpleGrantedAuthority(authority));
                    }
                }
            }
        }

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
}