package com.theodore.auth.server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class ProjectSecurityConfig {

    private static final String USERNAME = "username";
    private static final String ROLES = "roles";
    private static final String ORGANIZATION = "organization";
    private static final String AUTHORITIES = "authorities";


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
                                .oidc(Customizer.withDefaults())    // Enable OpenID Connect 1.0
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
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        http
                .csrf(csrfConfig -> csrfConfig
                        .ignoringRequestMatchers(request ->
                                request.getServletPath().startsWith("/user/")
                        )
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, "/user/register/**").hasAuthority("SCOPE_INTERNAL_SERVICE")
                        .requestMatchers(HttpMethod.PUT, "/user/confirm").hasAuthority("SCOPE_ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(jwtDecoder))
                );

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        /// JWT ///
        RegisteredClient clientCredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("mobility-api")
                .clientSecret("{noop}thes333crEt")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes(scopeConfig ->
                        scopeConfig.addAll(List.of(OidcScopes.OPENID, "INTERNAL_SERVICE")))
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10))
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build())
                //.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        ///////////////////////////
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
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
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
                context.getClaims().claim(ORGANIZATION, List.of("INTERNAL_SERVICE"));

                Set<String> scopes = determineScopes(context);

                context.getClaims().claim(ROLES, scopes);
                context.getClaims().claim(AUTHORITIES, scopes);

            } else if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())) {

                MobilityUserDetails principal = context.getPrincipal();

                context.getClaims().claim(USERNAME, principal.getEmail());
                if (principal.getOrganizationRegNumber() != null) {
                    context.getClaims().claim(ORGANIZATION, principal.getOrganizationRegNumber());
                }
                context.getClaims().claim(ROLES, principal.getRoles());

                principal.getAuthorities().forEach(authority -> {//todo remove it
                    System.out.println(">>>>>>>>> " + authority.getAuthority());
                });

                context.getClaims().claim(AUTHORITIES, principal.getAuthorities().stream()
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

}


//context.getClaims().claims(claims -> {
//        if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
//String clientId = context.getPrincipal().getName();
//                    claims.put("username", clientId);
//                    claims.put("organization", List.of("SYSTEM"));
//
//Object scopeClaim = context.getClaims().build().getClaim("scope");
//
//Set<String> scopes = switch (scopeClaim) {
//    case String scopeStr -> Set.of(scopeStr.split(" "));
//    case Collection<?> scopeList -> scopeList.stream()
//            .filter(Objects::nonNull)
//            .map(Object::toString)
//            .collect(Collectors.toUnmodifiableSet());
//    default -> Set.of();
//};
//
//                    claims.put("roles", scopes);
//                    claims.put("authorities", scopes);
//
//                } else if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())) {
//MobilityUserDetails principal = context.getPrincipal();
//
//                    context.getClaims().claim("username", principal.getEmail());
//        if (principal.getOrganizationRegNumber() != null) {
//        context.getClaims().claim("organization", principal.getOrganizationRegNumber());
//        }
//        context.getClaims().claim("roles", principal.getRoles());
//
//        principal.getAuthorities().forEach(authority -> {//todo remove it
//        System.out.println(">>>>>>>>> " + authority.getAuthority());
//        });
//
//        context.getClaims().claim("authorities", principal.getAuthorities().stream()
//                            .map(GrantedAuthority::getAuthority)
//                            .toList());
//        }
//        });