package com.side.cooknow.global.config.auth.filter;

import com.side.cooknow.domain.user.model.User;
import com.side.cooknow.global.FirebaseService;
import com.side.cooknow.global.config.auth.OauthAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

import java.io.IOException;
import java.util.Collections;

@Log4j2
@RequiredArgsConstructor
public class FirebaseFilter extends TokenFilter {
    private final FirebaseService firebaseService;

    @Override
    protected boolean authenticateToken(String authToken, HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String email = firebaseService.verifyToken(authToken);
        log.info("Firebase token verified");
        User user = new User(email);
        setAuthenticationAndContinueChain(new OauthAuthenticationToken(user, Collections.emptyList()), request, response, filterChain);
        return true;
    }
}