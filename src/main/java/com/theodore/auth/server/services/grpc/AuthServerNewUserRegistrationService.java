package com.theodore.auth.server.services.grpc;

import com.theodore.auth.server.services.UserAuthService;
import com.theodore.auth.server.utils.GrpcExceptionMapper;
import com.theodore.user.*;
import io.grpc.stub.StreamObserver;
import net.devh.boot.grpc.server.service.GrpcService;

@GrpcService
public class AuthServerNewUserRegistrationService extends AuthServerNewUserRegistrationGrpc.AuthServerNewUserRegistrationImplBase {

    private final UserAuthService userAuthService;

    public AuthServerNewUserRegistrationService(UserAuthService userAuthService) {
        this.userAuthService = userAuthService;
    }

    @Override
    public void createSimpleUser(CreateNewSimpleAuthUserRequest request, StreamObserver<AuthUserIdResponse> responseObserver) {
        var response = userAuthService.registerNewSimpleUser(request);
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void createOrganizationUser(CreateNewOrganizationAuthUserRequest request, StreamObserver<AuthUserIdResponse> responseObserver) {
        var response = userAuthService.registerNewOrganizationUser(request);
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void confirmUserAccount(ConfirmUserAccountRequest request, StreamObserver<UserConfirmationResponse> responseObserver) {
        UserConfirmationResponse response = getUserConfirmationResponse(request);
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void confirmOrganizationAdminAccount(ConfirmAdminAccountRequest request, StreamObserver<UserConfirmationResponse> responseObserver) {
        var response = userAuthService.confirmOrganizationAdminRegistration(request);
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    private UserConfirmationResponse getUserConfirmationResponse(ConfirmUserAccountRequest request) {
        try {
            return userAuthService.confirmRegistration(request);
        } catch (Exception e) {
            return GrpcExceptionMapper.userConfirmationErrorMap(e);
        }
    }

}
