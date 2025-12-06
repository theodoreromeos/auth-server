package com.theodore.auth.server.config.security;

import com.theodore.infrastructure.common.entities.modeltypes.RoleType;

import java.util.LinkedHashMap;
import java.util.Map;

public class GrpcSecurity {

    //LinkedHashMap because it preserves insertion order and a predictable behaviour is needed.
    private final Map<String, RoleType> methodPolicies = new LinkedHashMap<>();

    public static GrpcSecurity configure() {
        return new GrpcSecurity();
    }

    public GrpcSecurity permitAll(String method) {
        methodPolicies.put(method, null);
        return this;
    }

    public GrpcSecurity requireRole(String method, RoleType role) {
        methodPolicies.put(method, role);
        return this;
    }

    public Map<String, RoleType> build() {
        return methodPolicies;
    }

}
