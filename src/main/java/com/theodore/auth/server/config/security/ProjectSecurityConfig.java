package com.theodore.auth.server.config.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.theodore.racingmodel.entities.modeltypes.RoleType;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import net.devh.boot.grpc.server.serverfactory.GrpcServerConfigurer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import javax.crypto.SecretKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(RsaKeyProperties.class)
public class ProjectSecurityConfig {

    private final ResourceLoader resourceLoader;
    private final RsaKeyProperties rsaKeyProperties;

    private static final String USERNAME = "username";
    private static final String ROLES = "roles";
    private static final String ORGANIZATION = "organization";

    public ProjectSecurityConfig(RsaKeyProperties rsaKeyProperties, ResourceLoader resourceLoader) {
        this.rsaKeyProperties = rsaKeyProperties;
        this.resourceLoader = resourceLoader;
    }


    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, authorizationServer ->
                        authorizationServer
                                .oidc(Customizer.withDefaults()) // OpenID Connect 1
                )
                .authorizeHttpRequests(authorize ->
                        authorize
                                .anyRequest().authenticated()

                )
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );

        return http.build();
    }

    @Bean
    @Order(2)
    public GrpcServerConfigurer secureGrpcServer(JwtServerInterceptor interceptor) {
        return serverBuilder -> serverBuilder
                .intercept(interceptor)
                .executor(Executors.newVirtualThreadPerTaskExecutor());
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // JWT //

        // CLIENT_CREDENTIALS
        RegisteredClient clientCredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("mobility-api")
                .clientSecret("{noop}thes333crEt")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes(scopeConfig ->
                        scopeConfig.addAll(List.of(OidcScopes.OPENID, RoleType.INTERNAL_SERVICE.getScopeValue())))
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10))
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build())
                .build();

        // AUTHORIZATION_CODE
        RegisteredClient pkceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("mobility-public")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scopes(s -> {
                    s.add(OidcScopes.OPENID);
                    s.add(OidcScopes.EMAIL);
                })
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true).build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .refreshTokenTimeToLive(Duration.ofHours(8))
                        .reuseRefreshTokens(false)
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build())
                .build();

        return new InMemoryRegisteredClientRepository(clientCredClient, pkceClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {

        Resource privateKeyRes = resourceLoader.getResource(rsaKeyProperties.privateKeyPath());
        Resource publicKeyRes = resourceLoader.getResource(rsaKeyProperties.publicKeyPath());

        RSAPrivateKey privateKey = RsaKeyUtils.loadPrivateKey(privateKeyRes);
        RSAPublicKey publicKey = RsaKeyUtils.loadPublicKey(publicKeyRes);

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(rsaKeyProperties.keyId())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                return;
            }

            if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {

                String clientId = context.getPrincipal().getName();

                context.getClaims().claim(USERNAME, clientId);
                context.getClaims().claim(ORGANIZATION, List.of(RoleType.INTERNAL_SERVICE.getScopeValue()));

                Set<String> scopes = determineScopes(context);

                context.getClaims().claim(ROLES, scopes);

            } else if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())) {

                MobilityUserDetails principal = context.getPrincipal();

                context.getClaims().claim(USERNAME, principal.getEmail());
                if (principal.getOrganizationRegNumber() != null) {
                    context.getClaims().claim(ORGANIZATION, principal.getOrganizationRegNumber());
                }

                principal.getAuthorities().forEach(authority -> {//todo remove it
                    System.out.println(">>>>>>>>> " + authority.getAuthority());
                });

                context.getClaims().claim(ROLES, principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList());
            }
        };
    }

    private Set<String> determineScopes(JwtEncodingContext context) {
        Object scopeClaim = context.getClaims().build().getClaim("scope");
        return switch (scopeClaim) {
            case String scopeStr -> Set.of(scopeStr.split(" "));
            case Collection<?> scopeList -> scopeList.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .collect(Collectors.toUnmodifiableSet());
            default -> Set.of();
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }

    @Bean("emailJwtSigningKey")
    public SecretKey emailJwtSigningKey() {
        // For HS256; for production, load from Vault or ENV
        return Keys.secretKeyFor(SignatureAlgorithm.HS256);//TODO
    }

    @Bean("emailTokenValiditySeconds")
    public long emailTokenValiditySeconds(@Value("${app.email-token-lifetime-seconds:86400}") long ttl) {
        return ttl;
    }

    @Bean
    public Map<String, RoleType> grpcMethodPolicies() {
        return GrpcSecurity.configure()
                .requireRole("user.AuthServerNewUserRegistration/CreateSimpleUser", RoleType.INTERNAL_SERVICE)
                .requireRole("user.AuthServerNewUserRegistration/CreateOrganizationUser", RoleType.INTERNAL_SERVICE)
                .requireRole("user.AuthServerNewUserRegistration/CreateOrganizationAdmin", RoleType.INTERNAL_SERVICE)
                .requireRole("user.AuthServerNewUserRegistration/ConfirmUserAccount", RoleType.INTERNAL_SERVICE)
                .build();
    }

}