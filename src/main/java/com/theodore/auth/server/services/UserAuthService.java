package com.theodore.auth.server.services;

import com.theodore.user.*;

public interface UserAuthService {

    /**
     * Register a simple user's account credentials.
     *
     * @param newUserRequest contains the email, phone number and password
     */
    AuthUserIdResponse registerNewSimpleUser(CreateNewSimpleAuthUserRequest newUserRequest);

    /**
     * Register an organization user's account credentials.
     *
     * @param newUserRequest contains the organization registration number, email, phone number and password
     */
    AuthUserIdResponse registerNewOrganizationUser(CreateNewOrganizationAuthUserRequest newUserRequest);

    /**
     * Confirms/Verifies a user's account.
     *
     * @param request contains just the user's id
     */
    UserConfirmationResponse confirmRegistration(ConfirmUserAccountRequest request);

    /**
     * Confirms/Verifies an admin's account.
     *
     * @param request contains user's id , current password and new password
     */
    UserConfirmationResponse confirmOrganizationAdminRegistration(ConfirmAdminAccountRequest request);

    /**
     * Rolls back any registration done for a user.
     *
     * @param userId the user's id
     */
    void rollbackRegistration(String userId);

    /**
     * Updates an account's info.
     *
     * @param manageUserAccountRequest request that can change email, password and phone number of an account
     */
    AuthUserIdResponse manageAuthUserAccount(ManageAuthUserAccountRequest manageUserAccountRequest);

    /**
     * Fetches all email and ids of the admins of an organization
     *
     * @param orgRegistrationNumber the registration number of the organization
     */
    OrgAdminIdAndEmailResponse getOrganizationAdminInfo(String orgRegistrationNumber);

    void addUserRole(AddRoleRequest request);

}
