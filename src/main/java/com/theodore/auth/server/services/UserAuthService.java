package com.theodore.auth.server.services;

import com.theodore.user.*;

public interface UserAuthService {

    AuthUserCreatedResponse registerNewSimpleUser(CreateNewSimpleAuthUserRequest newUserRequest);

    AuthUserCreatedResponse registerNewOrganizationUser(CreateNewOrganizationAuthUserRequest newUserRequest);

    UserConfirmationResponse confirmRegistration(ConfirmUserAccountRequest request);

    void rollbackRegistration(String userId);

}
