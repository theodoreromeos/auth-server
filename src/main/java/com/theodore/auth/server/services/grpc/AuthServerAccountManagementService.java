package com.theodore.auth.server.services.grpc;

import com.theodore.auth.server.services.UserAuthService;
import com.theodore.user.AuthServerAccountManagementGrpc;
import com.theodore.user.AuthUserIdResponse;
import com.theodore.user.ManageAuthUserAccountRequest;
import io.grpc.stub.StreamObserver;
import net.devh.boot.grpc.server.service.GrpcService;

@GrpcService
public class AuthServerAccountManagementService extends AuthServerAccountManagementGrpc.AuthServerAccountManagementImplBase {

    private final UserAuthService userAuthService;

    public AuthServerAccountManagementService(UserAuthService userAuthService) {
        this.userAuthService = userAuthService;
    }

    @Override
    public void manageUserAccount(ManageAuthUserAccountRequest request, StreamObserver<AuthUserIdResponse> responseObserver) {
        var response = userAuthService.manageAuthUserAccount(request);
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }
}
