package com.theodore.auth.server.services.grpc;

import com.google.protobuf.Empty;
import com.theodore.auth.server.services.UserAuthService;
import com.theodore.user.*;
import io.grpc.stub.StreamObserver;
import net.devh.boot.grpc.server.service.GrpcService;

@GrpcService
public class AuthServerRoleService extends AuthServerRoleManagementGrpc.AuthServerRoleManagementImplBase {

    private final UserAuthService userAuthService;

    public AuthServerRoleService(UserAuthService userAuthService) {
        this.userAuthService = userAuthService;
    }

    @Override
    public void addRole(AddRoleRequest request, StreamObserver<Empty> responseObserver) {
        try {
            userAuthService.addUserRole(request);
            responseObserver.onNext(Empty.getDefaultInstance());
            responseObserver.onCompleted();
        } catch (Exception ex) {
            responseObserver.onError(
                    io.grpc.Status.INTERNAL
                            .withDescription(ex.getMessage())
                            .withCause(ex)
                            .asRuntimeException()
            );
        }
    }

}
