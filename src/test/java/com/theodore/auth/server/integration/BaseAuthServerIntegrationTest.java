package com.theodore.auth.server.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.theodore.auth.server.utils.AuthServerTestConfigs;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.RabbitMQContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "grpc.server.port=0")
@AutoConfigureWebTestClient(timeout = "40000")
@ActiveProfiles("test")
@Testcontainers
@Import(AuthServerTestConfigs.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class BaseAuthServerIntegrationTest {

    @Value("${server.servlet.context-path}")
    private String contextPath;
    @LocalServerPort
    private int port;

    @MockitoBean
    CompromisedPasswordChecker compromisedPasswordChecker;
    @Autowired
    protected WebTestClient webTestClient;
    @Autowired
    protected ObjectMapper objectMapper;
    @Autowired
    protected TestDataHelper testDataHelper;

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    @Container
    @ServiceConnection
    static RabbitMQContainer rabbit = new RabbitMQContainer("rabbitmq:4-alpine");

    @BeforeEach
    void setUp() {
        testDataHelper.initAuthData();
    }

    protected String baseUrl() {
        return "http://localhost:" + port + contextPath;
    }

}
