package com.theodore.auth.server.services;

import com.theodore.queue.common.authserver.CredentialsRollbackEventDto;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

@Component
public class UserManagementListener {

    private final UserAuthService userAuthService;

    public UserManagementListener(UserAuthService userAuthService) {
        this.userAuthService = userAuthService;
    }

    @RabbitListener(queues = "${rabbitmq.queue}")
    public void receive(CredentialsRollbackEventDto message) {
        System.out.println("RECEIVED ROLLBACK REQUEST");
        try {
            userAuthService.rollbackRegistration(message.userId());
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            throw new RuntimeException("Error: " + e.getMessage());//todo : souloupoma
        }

    }

}
