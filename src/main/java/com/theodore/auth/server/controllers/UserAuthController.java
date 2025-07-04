package com.theodore.auth.server.controllers;

import com.theodore.auth.server.services.UserAuthService;
import com.theodore.racingmodel.models.AuthUserCreatedResponseDto;
import com.theodore.racingmodel.models.CreateNewOrganizationAuthUserRequestDto;
import com.theodore.racingmodel.models.CreateNewSimpleAuthUserRequestDto;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
public class UserAuthController {

    private final UserAuthService userAuthService;

    public UserAuthController(UserAuthService userAuthService) {
        this.userAuthService = userAuthService;
    }

    @PostMapping("/register/simple")
    public ResponseEntity<AuthUserCreatedResponseDto> registerNewSimpleUser(@RequestBody @Valid CreateNewSimpleAuthUserRequestDto newUserRequestDto) {
        AuthUserCreatedResponseDto responseDto = userAuthService.registerNewSimpleUser(newUserRequestDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(responseDto);
    }

    @PostMapping("/register/organization")
    public ResponseEntity<AuthUserCreatedResponseDto> registerNewOrganizationUser(@RequestBody @Valid CreateNewOrganizationAuthUserRequestDto newUserRequestDto) {
        AuthUserCreatedResponseDto responseDto = userAuthService.registerNewOrganizationUser(newUserRequestDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(responseDto);
    }

    @PutMapping("/confirm")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void confirmUserAccount(@RequestParam String userId) {
        userAuthService.confirmRegistration(userId);
    }

}
