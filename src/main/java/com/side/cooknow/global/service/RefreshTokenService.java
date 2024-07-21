package com.side.cooknow.global.service;

import com.google.firebase.auth.FirebaseAuthException;
import com.side.cooknow.domain.user.model.User;
import com.side.cooknow.domain.user.service.UserService;
import com.side.cooknow.global.config.auth.AuthenticationFacade;
import com.side.cooknow.global.model.security.RefreshToken;
import com.side.cooknow.global.model.security.Token;
import com.side.cooknow.global.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${jwt.refresh-expiration}")
    private long refreshTokenExpiration;
    private final UserService userService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuthenticationFacade authenticationFacade;

    public void save(final RefreshToken refreshToken) {
        refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken createToken() throws FirebaseAuthException {
        User user = getUser();
        RefreshToken refreshToken = generateUniqueToken(user);
        save(refreshToken);
        return refreshToken;
    }

    @Transactional
    public void delete() {
        Long userId = authenticationFacade.getAuthenticatedUserId();
        User user = userService.findByUserId(userId);
        refreshTokenRepository.updateEmailByUser(user);
    }

    public RefreshToken findByToken(final String token) {
        return refreshTokenRepository.findByTokenAndDeletedAtIsNull(Token.of(token)).orElseThrow();
    }

    public boolean existsByToken(final String token) {
        Token refreshToken = new Token(token);
        return refreshTokenRepository.existsByTokenAndDeletedAtIsNull(refreshToken);
    }

    private RefreshToken generateUniqueToken(final User user) {
        RefreshToken refreshToken;
        do {
            refreshToken = RefreshToken.of(user, refreshTokenExpiration);
        } while (existsByToken(refreshToken.getTokenValue()));
        return refreshToken;
    }

    private User getUser() throws FirebaseAuthException {
        return userService.find();
    }


}