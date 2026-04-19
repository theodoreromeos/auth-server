package com.theodore.auth.server.config;

import com.theodore.queue.common.authserver.RollbackQueueConfig;
import com.theodore.queue.common.config.CommonRabbitMqConfigs;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({CommonRabbitMqConfigs.class, RollbackQueueConfig.class})
public class RabbitMqAutoConfiguration {
}
