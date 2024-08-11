package com.side.cooknow.global.controller;

import com.google.firebase.auth.FirebaseAuthException;
import com.side.cooknow.domain.user.exception.UserErrorCode;
import com.side.cooknow.domain.user.exception.UserException;
import com.side.cooknow.domain.user.model.User;
import com.side.cooknow.domain.user.service.UserService;
import com.side.cooknow.global.config.auth.AuthenticationFacade;
import com.side.cooknow.global.model.dto.request.RequestRefresh;
import com.side.cooknow.global.model.dto.request.RequestWithdraw;
import com.side.cooknow.global.model.dto.response.ResponseSignIn;
import com.side.cooknow.global.model.dto.response.ResponseRefresh;
import com.side.cooknow.global.model.dto.response.ResponseSignOut;
import com.side.cooknow.global.model.dto.response.ResponseWithdraw;
import com.side.cooknow.global.model.security.RefreshToken;
import com.side.cooknow.global.service.JwtTokenService;
import com.side.cooknow.global.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Stack;

@Log4j2
@RestController
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final JwtTokenService jwtTokenService;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;
    private final AuthenticationFacade authenticationFacade;

    @PostMapping("/sign-in")
    public ResponseEntity<ResponseSignIn> signIn() throws FirebaseAuthException {
        User user = authenticationFacade.getAuthenticatedUser();
        if (!userService.existsByEmail(user.getEmail())) {
            user = userService.save(user.getEmail());
        } else {
            user = userService.findByEmail(user.getEmail());
        }
        String accessToken = jwtTokenService.createAccessToken(user);
        refreshTokenService.deleteAllByEmail(user);
        RefreshToken refreshToken = refreshTokenService.createToken(user);
        ResponseSignIn responseDto = new ResponseSignIn(accessToken, refreshToken);
        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }

    @PostMapping("/refresh")
    public ResponseEntity<ResponseRefresh> refresh() {
        User user = authenticationFacade.getAuthenticatedUser();
//        isValidateRequest(user, requestDto.getEmail());
        String accessToken = jwtTokenService.refreshAccessToken(user);
        ResponseRefresh responseDto = new ResponseRefresh(accessToken);

        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }

    @PostMapping("/sign-out")
    public ResponseEntity<ResponseSignOut> signOut() {
        User user = authenticationFacade.getAuthenticatedUser();
        refreshTokenService.deleteAllByUser(user);
        return ResponseEntity.ok(new ResponseSignOut());
    }

    @PostMapping("/withdraw")
    public ResponseEntity<ResponseWithdraw> withdraw() {
        User user = authenticationFacade.getAuthenticatedUser();
//        isValidateRequest(user, requestDto.getEmail());
        userService.delete(user);
        refreshTokenService.deleteAllByUser(user);
        return ResponseEntity.ok(new ResponseWithdraw());
    }

    private void isValidateRequest(final User user, final String email) {
        if (!user.isValidateRequest(email)) {
            throw new UserException(UserErrorCode.INVALID_REQUEST);
        }
    }
}
