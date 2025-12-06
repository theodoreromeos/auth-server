package com.theodore.auth.server.utils;

import com.theodore.infrastructure.common.exceptions.NotFoundException;
import com.theodore.user.ConfirmationStatus;
import com.theodore.user.UserConfirmationResponse;

public class GrpcExceptionMapper {

    public static UserConfirmationResponse userConfirmationErrorMap(Exception ex) {
        if (ex instanceof NotFoundException) {
            return UserConfirmationResponse.newBuilder()
                    .setConfirmationStatus(ConfirmationStatus.CONFIRMATION_FAILED)
                    .build();
        }
        return UserConfirmationResponse.newBuilder()
                .setConfirmationStatus(ConfirmationStatus.CONFIRMATION_FAILED)
                .build();
    }

}
