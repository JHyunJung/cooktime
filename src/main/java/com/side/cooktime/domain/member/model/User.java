package com.side.cooktime.domain.member.model;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.OneToOne;
import lombok.Getter;

@Entity
@Getter
public class User extends Member {

    @OneToOne(mappedBy = "user", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    private UserGoogleInfo userGoogleInfo;

    //Google
    public User(final UserGoogleInfo userGoogleInfo, final String email, final String givenName, final String familyName) {
        super(Role.USER, email, "Google_Sign_Up", givenName, familyName);
        this.userGoogleInfo = userGoogleInfo.withUser(this);
    }

    protected User() {
        ;
    }

    public static User ofGoogle(String email, String givenName, String familyName, UserGoogleInfo userGoogleInfo) {
        return new User(userGoogleInfo, email, givenName, familyName);
    }
}
