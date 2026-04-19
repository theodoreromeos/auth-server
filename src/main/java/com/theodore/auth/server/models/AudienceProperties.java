package com.theodore.auth.server.models;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Map;

@ConfigurationProperties(prefix = "token.resources")
public record AudienceProperties(Map<String, List<String>> allowedTargets, String mobilityPublicApi) {

    /**
     * key   = client_id (mobility-api)
     * value = list of resource identifiers
     */
    public boolean isAllowed(String clientId, String resource) {
        List<String> allowed = allowedTargets.getOrDefault(clientId, List.of());
        return allowed.contains(resource);
    }

}
