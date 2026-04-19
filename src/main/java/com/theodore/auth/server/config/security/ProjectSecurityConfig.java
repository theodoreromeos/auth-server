package com.theodore.auth.server.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.theodore.auth.server.models.AudienceProperties;
import com.theodore.auth.server.models.CsrfCookieProperties;
import com.theodore.auth.server.models.RsaKeyProperties;
import com.theodore.auth.server.models.TokenTtlProperties;
import com.theodore.auth.server.utils.MobilityUserDetailsMixIn;
import com.theodore.auth.server.utils.PermissionsPolicy;
import com.theodore.infrastructure.common.entities.enums.RoleType;
import jakarta.servlet.http.HttpServletResponse;
import net.devh.boot.grpc.server.serverfactory.GrpcServerConfigurer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
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
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
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
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy;
import org.springframework.security.web.header.writers.CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties({RsaKeyProperties.class, TokenTtlProperties.class, AudienceProperties.class, CsrfCookieProperties.class})
public class ProjectSecurityConfig {

    private final RsaKeyProperties rsaKeyProperties;
    private final TokenTtlProperties tokenTtlProperties;
    private final String issuerUrl;

    private static final String ROLES = "roles";
    private static final String ORGANIZATION = "organization";
    private static final String RESOURCE = "resource";

    public ProjectSecurityConfig(RsaKeyProperties rsaKeyProperties,
                                 TokenTtlProperties tokenTtlProperties,
                                 @Value("${issuer.url}") String issuerUrl) {
        this.rsaKeyProperties = rsaKeyProperties;
        this.tokenTtlProperties = tokenTtlProperties;
        this.issuerUrl = issuerUrl;
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
                .cors(Customizer.withDefaults())
                // Redirect to the login page when not authenticated from the authorization endpoint
                .exceptionHandling(exceptions ->
                        exceptions.defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'none'; " +
                                        "frame-ancestors 'none'; " +
                                        "form-action 'self'; " +
                                        "base-uri 'none'"))
                        .referrerPolicy(ref -> ref.policy(ReferrerPolicy.NO_REFERRER))
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .preload(true)
                                .maxAgeInSeconds(31536000))
                        .permissionsPolicyHeader(permissions -> permissions.policy(
                                PermissionsPolicy.buildPermissionsPolicy()))
                );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http, CookieCsrfTokenRepository csrfRepo) throws Exception {

        http
                .securityMatcher("/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login",
                                "/login/**",
                                "/assets/**",
                                "/error").permitAll()
                        .anyRequest().authenticated()
                )
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfRepo)
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                        .ignoringRequestMatchers("/api/auth/login") //todo: remove it
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/api/auth/login")
                        .successHandler((request, response, authentication) -> {
                            response.setStatus(HttpServletResponse.SC_OK);
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                            response.getWriter().write("{\"status\":\"success\"}");
                        })
                        .failureHandler((request, response, exception) -> {
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                            response.getWriter().write("{\"status\":\"failed\"}");
                        })
                        .permitAll())
                .sessionManagement(session -> session
                        .sessionFixation().changeSessionId()
                        .maximumSessions(5)
                        .maxSessionsPreventsLogin(false)
                )
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'self'; " +
                                        "script-src 'self'; " +
                                        "style-src 'self'; " +
                                        "img-src 'self' data:; " +
                                        "font-src 'self'; " +
                                        "connect-src 'self'; " +
                                        "frame-ancestors 'none'; " +
                                        "form-action 'self'; " +
                                        "base-uri 'self'; " +
                                        "object-src 'none'"))
                        .referrerPolicy(ref -> ref.policy(ReferrerPolicy.NO_REFERRER))
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .preload(true)
                                .maxAgeInSeconds(31536000))
                        .permissionsPolicyHeader(permissions -> permissions.policy(
                                PermissionsPolicy.buildPermissionsPolicy()))
                        .crossOriginOpenerPolicy(coop -> coop.policy(
                                CrossOriginOpenerPolicy.SAME_ORIGIN))
                        .crossOriginResourcePolicy(corp -> corp.policy(
                                CrossOriginResourcePolicy.SAME_ORIGIN))
                );
        return http.build();
    }

    @Bean
    public CookieCsrfTokenRepository createCookieCsrfTokenRepository(CsrfCookieProperties properties) {
        var csrfRepo = CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfRepo.setCookieCustomizer(cookie -> cookie
                .sameSite(properties.sameSite())
                .secure(properties.secure())
        );
        return csrfRepo;
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
                        .accessTokenTimeToLive(tokenTtlProperties.clientCredentialsAccess())
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
                        .accessTokenTimeToLive(tokenTtlProperties.pkceAccess())
                        .refreshTokenTimeToLive(tokenTtlProperties.pkceRefresh())
                        .reuseRefreshTokens(false)
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .build())
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        try {
            RSAKey rsaKey = new RSAKey.Builder(rsaKeyProperties.publicKey())
                    .privateKey(rsaKeyProperties.privateKey())
                    .keyIDFromThumbprint()
                    .keyUse(KeyUse.SIGNATURE)       // /oauth2/jwks publishes keys with no declared algorithm or use, which breaks strict client-side JWK validation
                    .algorithm(JWSAlgorithm.RS256)  // and is non-compliant with RFC 7517.
                    .build();
            JWKSet jwkSet = new JWKSet(rsaKey);
            return new ImmutableJWKSet<>(jwkSet);
        } catch (JOSEException ex) {
            throw new IllegalStateException("Failed to compute JWK thumbprint for RSA key", ex);
        }
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource,
                                 @Value("${grpc.expected-audience}") String expectedAudience) {

        NimbusJwtDecoder decoder = (NimbusJwtDecoder) OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);

        OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<List<String>>(
                JwtClaimNames.AUD, aud -> aud != null && aud.contains(expectedAudience));

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuerUrl),
                audienceValidator));

        return decoder;
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer(issuerUrl).build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(AudienceProperties audienceProps) {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                customizeAccessToken(context, audienceProps);
            } else if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                customizeOpenIdToken(context);
            }
        };
    }

    private void customizeAccessToken(JwtEncodingContext context, AudienceProperties audienceProps) {
        if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {

            context.getClaims().subject(context.getPrincipal().getName());

            Set<String> scopes = determineScopes(context);

            context.getClaims().claim(ROLES, scopes);

            setAudienceClaim(context, audienceProps);

        } else if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())) {

            Authentication principal = context.getPrincipal();
            Object principalObj = principal.getPrincipal();
            if (principalObj instanceof MobilityUserDetails mobilityUserDetails) {
                context.getClaims().subject(mobilityUserDetails.getAuthUserId());
                if (mobilityUserDetails.getOrganizationRegNumber() != null) {
                    context.getClaims().claim(ORGANIZATION, mobilityUserDetails.getOrganizationRegNumber());
                }
                context.getClaims().claim(ROLES, mobilityUserDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList());
            }
            context.getClaims().audience(List.of(audienceProps.mobilityPublicApi()));
        }
    }

    private void customizeOpenIdToken(JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();
        context.getClaims().audience(List.of(context.getRegisteredClient().getClientId()));
        if (principal.getPrincipal() instanceof MobilityUserDetails user) {
            context.getClaims().claim(StandardClaimNames.EMAIL, user.getEmail());
            context.getClaims().claim(StandardClaimNames.EMAIL_VERIFIED, true);//todo: have the actual value of the email verified here
            context.getClaims().subject(user.getAuthUserId());
            if (user.getOrganizationRegNumber() != null) {
                context.getClaims().claim(ORGANIZATION, user.getOrganizationRegNumber());
            }
        }
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

    private void setAudienceClaim(JwtEncodingContext context, AudienceProperties audienceProps) {
        String clientId = context.getRegisteredClient().getClientId();
        String targetResource = getTargetResource(context);

        if (!audienceProps.isAllowed(clientId, targetResource)) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_CLIENT,
                    "Client %s is not permitted to target resource %s".formatted(clientId, targetResource),
                    null));
        }

        context.getClaims().audience(List.of(targetResource));
    }

    private String getTargetResource(JwtEncodingContext context) {
        OAuth2ClientCredentialsAuthenticationToken grant = context.getAuthorizationGrant();

        Map<String, Object> additionalParams = grant.getAdditionalParameters();
        Object resourceParam = additionalParams.get(RESOURCE);

        if (resourceParam == null || resourceParam.toString().isBlank()) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "The resource parameter is required for client_credentials grants",
                    null));
        }
        return resourceParam.toString();
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

    @Bean
    public CorsConfigurationSource corsConfigurationSource(@Value("${cors.allowed-origins}") List<String> allowedOrigins) {

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        config.setAllowedHeaders(List.of(
                HttpHeaders.AUTHORIZATION,
                HttpHeaders.CONTENT_TYPE,
                "X-XSRF-TOKEN"
        ));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

}