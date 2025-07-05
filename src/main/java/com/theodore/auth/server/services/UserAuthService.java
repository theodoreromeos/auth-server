package com.theodore.auth.server.services;

import com.theodore.racingmodel.models.AuthUserCreatedResponseDto;
import com.theodore.racingmodel.models.CreateNewOrganizationAuthUserRequestDto;
import com.theodore.racingmodel.models.CreateNewSimpleAuthUserRequestDto;

public interface UserAuthService {

    AuthUserCreatedResponseDto registerNewSimpleUser(CreateNewSimpleAuthUserRequestDto newUserRequestDto);

    AuthUserCreatedResponseDto registerNewOrganizationUser(CreateNewOrganizationAuthUserRequestDto userRequestDto);

    void confirmRegistration(String userId);

    void rollbackRegistration(String userId);

}
