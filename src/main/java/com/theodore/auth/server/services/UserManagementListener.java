package com.theodore.auth.server.services;

import com.theodore.queue.common.authserver.CredentialsRollbackEventDto;
import com.theodore.racingmodel.exceptions.RollbackProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

@Component
public class UserManagementListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserManagementListener.class);

    private final UserAuthService userAuthService;

    public UserManagementListener(UserAuthService userAuthService) {
        this.userAuthService = userAuthService;
    }

    @RabbitListener(queues = "${rabbitmq.queue}")
    public void receive(CredentialsRollbackEventDto message) {
        LOGGER.trace("Received rollback request");
        try {
            userAuthService.rollbackRegistration(message.userId());
        } catch (Exception e) {
            LOGGER.error("Failed to rollback user registration for userId={}: {}", message.userId(), e);
            throw new RollbackProcessingException("Failed to rollback registration for userId=" + message.userId(), e);
        }
    }

}
