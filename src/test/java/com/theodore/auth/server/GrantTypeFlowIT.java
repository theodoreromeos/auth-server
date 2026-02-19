package com.theodore.auth.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.theodore.utils.TestData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.ExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.StreamSupport;

import static org.assertj.core.api.Assertions.assertThat;

class GrantTypeFlowIT extends BaseAuthServerIntegrationTest {

    private static final String REDIRECT_URI = "http://localhost:9999/login/callback";

    WebTestClient client;

    @BeforeAll
    void initClient() {
        client = webTestClient.mutate().baseUrl(baseUrl()).build();
    }

    @Test
    @DisplayName("simple user full PKCE flow: login -> authorize -> exchange code -> verify JWT claims")
    void givenValidSimpleUserCredentials_whenDoingFullPkceFlow_issueJwt() throws Exception {
        // given
        var pkce = PkceTestModel.createPkceTestModel();

        // when steps

        // Step 1: Login and get a session client
        var sessionClient = loginSuccessfully(TestData.SIMPLE_USER_TEST_EMAIL, TestData.TEST_PASSWORD);

        // Step 2: Request authorization code
        // The auth server validates the session, generates a code, persists
        // the authorization and redirects back with the code
        var redirect = authorize(sessionClient, pkce.challenge(), "test-state");

        var authorizationCode = queryParam(redirect, "code");
        var returnedState = queryParam(redirect, "state");
        assertThat(returnedState).isEqualTo("test-state");

        // Step 3: Exchange authorization code for tokens
        // The authorization is read from the database
        // code_verifier is verified against the stored code_challenge, and issues tokens.
        var tokenResponse = getTokenResponse(sessionClient, authorizationCode, pkce.verifier());

        // then
        assertThat(tokenResponse.path("access_token").asText()).isNotBlank();
        assertThat(tokenResponse.path("id_token").asText()).isNotBlank();
        assertThat(tokenResponse.path("token_type").asText()).isEqualTo("Bearer");

        var claims = decodeJwt(tokenResponse.path("access_token").asText());

        assertThat(claims).isNotNull();

        String username = claims.path("username").asText(null);
        assertThat(username).isEqualTo(TestData.SIMPLE_USER_TEST_EMAIL);

        String organization = claims.path("organization").asText(null);

        assertThat(organization).isNull();


        var roles = claims.path("roles");
        assertThat(roles.isArray()).isTrue();

        boolean hasSimpleUserRole = StreamSupport.stream(roles.spliterator(), false)
                .map(JsonNode::asText)
                .anyMatch("SIMPLE_USER"::equals);

        assertThat(hasSimpleUserRole).isTrue();
    }

    @Test
    @DisplayName("organization user full PKCE flow: login -> authorize -> exchange code -> verify JWT claims")
    void givenValidOrgUserCredentials_whenDoingFullPkceFlow_issueJwt() throws Exception {
        // given
        var pkce = PkceTestModel.createPkceTestModel();

        // when steps

        // Step 1: Login and get a session client
        var sessionClient = loginSuccessfully(TestData.ORG_USER_TEST_EMAIL, TestData.TEST_PASSWORD);

        // Step 2: Request authorization code
        // The auth server validates the session, generates a code, persists
        // the authorization and redirects back with the code
        var redirect = authorize(sessionClient, pkce.challenge(), "test-state");

        var authorizationCode = queryParam(redirect, "code");
        var returnedState = queryParam(redirect, "state");
        assertThat(returnedState).isEqualTo("test-state");

        // Step 3: Exchange authorization code for tokens
        // The authorization is read from the database
        // code_verifier is verified against the stored code_challenge, and issues tokens.
        var tokenResponse = getTokenResponse(sessionClient, authorizationCode, pkce.verifier());

        // then
        assertThat(tokenResponse.path("access_token").asText()).isNotBlank();
        assertThat(tokenResponse.path("id_token").asText()).isNotBlank();
        assertThat(tokenResponse.path("token_type").asText()).isEqualTo("Bearer");

        var claims = decodeJwt(tokenResponse.path("access_token").asText());

        assertThat(claims).isNotNull();

        String username = claims.path("username").asText(null);
        assertThat(username).isNotNull().isEqualTo(TestData.ORG_USER_TEST_EMAIL);

        String organization = claims.path("organization").asText(null);
        assertThat(organization).isNotNull().isEqualTo(TestData.TEST_ORG_REG_NUMBER);

        var roles = claims.path("roles");
        assertThat(roles).isNotNull();
        assertThat(roles.isArray()).isTrue();

        boolean hasMechanicRole = StreamSupport.stream(roles.spliterator(), false)
                .map(JsonNode::asText)
                .anyMatch("MECHANIC"::equals);

        assertThat(hasMechanicRole).isTrue();
    }

    @Test
    @DisplayName("Authorization process: Given invalid credentials the login fails and should return 401 and not create a session")
    void givenInvalidCredentials_whenLogin_returnUnauthorized() {
        var result = client.post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("username", TestData.SIMPLE_USER_TEST_EMAIL)
                        .with("password", "WRONG_PASSWORD"))
                .exchange()
                .expectStatus().isUnauthorized()
                .returnResult(Void.class);

        var sessionCookie = result.getResponseCookies().getFirst("JSESSIONID");
        assertThat(sessionCookie).isNull();

        var setCookieHeaders = result.getResponseHeaders().get("Set-Cookie");
        if (setCookieHeaders != null) {
            assertThat(setCookieHeaders.stream().anyMatch(h -> h.startsWith("JSESSIONID="))).isFalse();
        }
    }

    @Test
    @DisplayName("Authorization process: After successful login and recieing auth code, given wrong verifier in step 3 should reject token exchange with invalid_grant")
    void givenIncorrectVerifier_whenAttemptingTheTokenExchange_returnBadRequest() throws Exception {
        // given
        var pkce = PkceTestModel.createPkceTestModel();

        // when steps

        // Step 1: Login and get a session client
        var sessionClient = loginSuccessfully(TestData.SIMPLE_USER_TEST_EMAIL, TestData.TEST_PASSWORD);

        // Step 2: Request authorization code
        // The auth server validates the session, generates a code, persists
        // the authorization and redirects back with the code
        var redirect = authorize(sessionClient, pkce.challenge(), "state-1");
        var authorizationCode = queryParam(redirect, "code");
        // DIFFERENT verifier than the one used to create the challenge
        var otherVerifier = PkceTestModel.createPkceTestModel().verifier();

        // Step 3
        var exchange = sessionClient.post()
                .uri("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                        .with("code", authorizationCode)
                        .with("redirect_uri", REDIRECT_URI)
                        .with("client_id", "mobility-public")
                        .with("code_verifier", otherVerifier))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isNotEmpty()
                .returnResult();

        // then

        var body = exchange.getResponseBody();
        if (body != null) {
            var json = objectMapper.readTree(body);
            var errorTxt = json.path("error").asText();
            assertThat(errorTxt).isIn("invalid_grant", "invalid_request");
        }
    }

    // ==========================================  STEPS  ==========================================

    // STEP 1
    private WebTestClient loginSuccessfully(String username, String password) {
        ExchangeResult result = client.post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("username", username).with("password", password))
                .exchange()
                .expectStatus().is2xxSuccessful()
                .returnResult(Void.class);

        var sessionCookie = result.getResponseCookies().getFirst("JSESSIONID");
        assertThat(sessionCookie).isNotNull();

        return client.mutate()
                .defaultCookie("JSESSIONID", sessionCookie.getValue())
                .build();
    }

    // STEP 2
    private URI authorize(WebTestClient sessionClient, String codeChallenge, String state) {
        var result = sessionClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", "mobility-public")
                        .queryParam("scope", "openid email")
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("code_challenge", codeChallenge)
                        .queryParam("code_challenge_method", "S256")
                        .queryParam("state", state)
                        .build())
                .exchange()
                .expectStatus().is3xxRedirection()
                .returnResult(Void.class);

        assertThat(result).isNotNull();
        assertThat(result.getResponseHeaders()).isNotNull();
        assertThat(result.getResponseHeaders().getLocation()).isNotNull();

        return result.getResponseHeaders().getLocation();
    }

    // STEP 3
    private JsonNode getTokenResponse(WebTestClient sessionClient, String authorizationCode, String codeVerifier) throws Exception {
        byte[] body = sessionClient.post()
                .uri("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                        .with("code", authorizationCode)
                        .with("redirect_uri", REDIRECT_URI)
                        .with("client_id", "mobility-public")
                        .with("code_verifier", codeVerifier))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.access_token").isNotEmpty()
                .jsonPath("$.id_token").isNotEmpty()
                .jsonPath("$.token_type").isEqualTo("Bearer")
                .returnResult()
                .getResponseBody();

        assertThat(body).isNotNull();
        return objectMapper.readTree(body);
    }

    // ========================================================================================================================

    private JsonNode decodeJwt(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format.Got '%s' parts instead of 3 parts.".formatted(parts.length));
        }
        var payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        return objectMapper.readTree(payload);
    }

    private String queryParam(URI uri, String name) {
        var params = UriComponentsBuilder.fromUri(uri).build().getQueryParams();
        var value = params.getFirst(name);
        if (value == null) {
            throw new IllegalArgumentException("Missing query param '%s' in redirect: %s".formatted(name, uri));
        }
        return value;
    }

}
