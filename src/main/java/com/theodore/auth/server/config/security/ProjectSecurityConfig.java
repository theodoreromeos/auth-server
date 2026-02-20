package com.theodore.auth.server.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.theodore.auth.server.utils.MobilityUserDetailsMixIn;
import com.theodore.infrastructure.common.entities.modeltypes.RoleType;
import net.devh.boot.grpc.server.serverfactory.GrpcServerConfigurer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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
        var authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, authorizationServer ->
                        authorizationServer.oidc(Customizer.withDefaults()) // OpenID Connect 1
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/login/**", "/error").permitAll()
                        .anyRequest().authenticated()
                )
                // Redirect to the login page when not authenticated from the authorization endpoint
                .exceptionHandling(exceptions ->
                        exceptions.defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .csrf(csrf ->
                        csrf.ignoringRequestMatchers("/oauth2/token", "/oauth2/introspect", "/oauth2/revoke"));

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
        var csrfRepo = CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfRepo.setCookiePath("/auth");
        csrfRepo.setCookieName("XSRF-TOKEN");

        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login",
                                "/login/**",
                                "/api/auth/login",
                                "/assets/**",
                                "/error",
                                "/oauth2/**",
                                "/.well-known/**").permitAll()
                        .anyRequest().authenticated())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfRepo)
                        .ignoringRequestMatchers("/login", "/api/auth/login")
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/api/auth/login")
                        .successHandler((request, response, authentication) -> {
                            response.setStatus(200);
                            response.setContentType("application/json");
                            response.getWriter().write("{\"status\":\"success\"}");
                        })
                        .failureHandler((request, response, exception) -> {
                            response.setStatus(401);
                            response.setContentType("application/json");
                            response.getWriter().write("{\"status\":\"failed\"}");
                        })
                        .permitAll());
        return http.build();
    }

    @Bean
    public GrpcServerConfigurer secureGrpcServer(JwtServerInterceptor interceptor) {
        return serverBuilder -> serverBuilder
                .intercept(interceptor)
                .executor(Executors.newVirtualThreadPerTaskExecutor());
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate, RegisteredClientRepository clientRepo) {
        JdbcOAuth2AuthorizationService service =
                new JdbcOAuth2AuthorizationService(jdbcTemplate, clientRepo);

        JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper rowMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(clientRepo);

        ObjectMapper objectMapper = new ObjectMapper();
        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
        objectMapper.registerModules(SecurityJackson2Modules.getModules(classLoader));
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        objectMapper.addMixIn(MobilityUserDetails.class, MobilityUserDetailsMixIn.class);

        rowMapper.setObjectMapper(objectMapper);
        service.setAuthorizationRowMapper(rowMapper);

        return service;
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbcTemplate, RegisteredClientRepository clientRepo) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, clientRepo);
    }

    @Bean
    public ApplicationRunner grantTypeFlowFeeder(RegisteredClientRepository repository,
                                                 PasswordEncoder passwordEncoder,
                                                 @Value("${oauth2.client.mobility-api.secret}") String apiSecret,
                                                 @Value("${oauth2.redirect.uri}") String redirectUri,
                                                 @Value("${oauth2.redirect.logout.uri}") String logoutUri) {
        return args -> {
            if (repository.findByClientId("mobility-api") == null) {
                var clientCredentials = createClientCredentials(passwordEncoder, apiSecret);
                repository.save(clientCredentials);
            }
            if (repository.findByClientId("mobility-public") == null) {
                var pkceClient = createPkceClient(redirectUri, logoutUri);
                repository.save(pkceClient);
            }
        };
    }

    private RegisteredClient createClientCredentials(PasswordEncoder passwordEncoder, String apiSecret) {
        return RegisteredClient
                .withId("mobility-api-id")
                .clientId("mobility-api")
                .clientSecret(passwordEncoder.encode(apiSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes(scope -> scope.add(RoleType.INTERNAL_SERVICE.getScopeValue()))
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .build())
                .build();
    }

    private RegisteredClient createPkceClient(String redirectUri, String logoutUri) {
        return RegisteredClient
                .withId("mobility-public-id")
                .clientId("mobility-public")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(redirectUri)
                .postLogoutRedirectUri(logoutUri)
                .scopes(s -> {
                    s.add(OidcScopes.OPENID);
                    s.add(OidcScopes.EMAIL);
                })
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(100))
                        .refreshTokenTimeToLive(Duration.ofHours(8))
                        .reuseRefreshTokens(false)
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .build())
                .build();
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
    public AuthorizationServerSettings authorizationServerSettings(@Value("${issuer.url}") String issuerUrl) {
        return AuthorizationServerSettings.builder().issuer(issuerUrl).build();
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

                Set<String> scopes = determineScopes(context);

                context.getClaims().claim(ROLES, scopes);

            } else if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())) {

                Authentication principal = context.getPrincipal();
                Object principalObj = principal.getPrincipal();
                if (principalObj instanceof MobilityUserDetails mobilityUserDetails) {
                    context.getClaims().claim(USERNAME, mobilityUserDetails.getEmail());
                    if (mobilityUserDetails.getOrganizationRegNumber() != null) {
                        context.getClaims().claim(ORGANIZATION, mobilityUserDetails.getOrganizationRegNumber());
                    }
                    context.getClaims().claim(ROLES, mobilityUserDetails.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .toList());
                }
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
    public SecretKey emailJwtSigningKey(@Value("${jwt.signing.secret.key}") String secret) {
        return new SecretKeySpec(Base64.getDecoder().decode(secret), "HmacSHA256");
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
                .requireRole("user.AuthServerNewUserRegistration/ConfirmOrganizationAdminAccount", RoleType.INTERNAL_SERVICE)
                .requireRole("user.AuthServerNewUserRegistration/GetAdminIdAndEmails", RoleType.INTERNAL_SERVICE)
                .requireRole("user.AuthServerAccountManagement/ManageUserAccount", RoleType.INTERNAL_SERVICE)
                .requireRole("user.AuthServerRoleManagement/AddRole", RoleType.INTERNAL_SERVICE)
                .build();
    }

}