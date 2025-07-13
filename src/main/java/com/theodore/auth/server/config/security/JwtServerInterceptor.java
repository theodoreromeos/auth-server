package com.theodore.auth.server.config.security;

import com.theodore.racingmodel.entities.modeltypes.RoleType;
import io.grpc.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class JwtServerInterceptor implements ServerInterceptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtServerInterceptor.class);

    private final JwtDecoder jwtDecoder;
    private final Map<String, RoleType> grpcServicePolicies;

    public JwtServerInterceptor(JwtDecoder jwtDecoder, Map<String, RoleType> grpcServicePolicies) {
        this.jwtDecoder = jwtDecoder;
        this.grpcServicePolicies = grpcServicePolicies;
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call,
            Metadata headers,
            ServerCallHandler<ReqT, RespT> next) {

        String methodName = call.getMethodDescriptor().getFullMethodName();
        String authHeader = headers.get(Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER));

        if (isInvalidAuthHeader(authHeader)) {
            return closeCallWithError(call, Status.UNAUTHENTICATED, "authorization header not correct");
        }

        String token = authHeader.substring(7);
        try {
            Jwt jwt = jwtDecoder.decode(token);
            List<String> scopes = jwt.getClaimAsStringList("scope");

            if (!hasRequiredScope(methodName, scopes)) {
                return closeCallWithError(call, Status.PERMISSION_DENIED, "scope missing");
            }

            return Contexts.interceptCall(Context.current(), call, headers, next);

        } catch (JwtException e) {
            return closeCallWithError(call, Status.UNAUTHENTICATED, "jwt error");
        }
    }

    private <ReqT, RespT> ServerCall.Listener<ReqT> closeCallWithError(ServerCall<ReqT, RespT> call, Status status, String logMessage) {
        LOGGER.error(logMessage);
        call.close(status, new Metadata());
        return new ServerCall.Listener<>() {
        };
    }


    private boolean isInvalidAuthHeader(String authHeader) {
        return authHeader == null || !authHeader.startsWith("Bearer ");
    }

    private boolean hasRequiredScope(String method, List<String> scopes) {
        RoleType requiredAuthority = grpcServicePolicies.get(method);
        LOGGER.info("the method name : {}", method);
        LOGGER.info("the required scopes : {}", scopes);
        if (requiredAuthority == null) {
            LOGGER.error("required authority is null");
            return false;
        }
        LOGGER.info("the required authority : {}", requiredAuthority.getScopeValue());
        if (scopes == null || scopes.isEmpty()) {
            return false;
        }
        return scopes.contains(requiredAuthority.getScopeValue());
    }
}
