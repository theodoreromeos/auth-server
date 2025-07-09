package com.theodore.auth.server.config.security;

import com.theodore.queue.common.authserver.CredentialsQueueConfig;
import com.theodore.queue.common.config.CommonRabbitMqConfigs;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({CommonRabbitMqConfigs.class, CredentialsQueueConfig.class})
public class RabbitMqAutoConfiguration {
}
