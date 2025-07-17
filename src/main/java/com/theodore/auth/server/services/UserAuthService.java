package com.theodore.auth.server.services;

import com.theodore.user.*;

public interface UserAuthService {

    AuthUserIdResponse registerNewSimpleUser(CreateNewSimpleAuthUserRequest newUserRequest);

    AuthUserIdResponse registerNewOrganizationUser(CreateNewOrganizationAuthUserRequest newUserRequest);

    UserConfirmationResponse confirmRegistration(ConfirmUserAccountRequest request);

    UserConfirmationResponse confirmOrganizationAdminRegistration(ConfirmAdminAccountRequest request);

    void rollbackRegistration(String userId);

    AuthUserIdResponse manageAuthUserAccount(ManageAuthUserAccountRequest manageUserAccountRequest);

}
