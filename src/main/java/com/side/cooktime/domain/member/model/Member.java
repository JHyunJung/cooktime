package com.side.cooktime.domain.member.model;

import com.side.cooktime.domain.model.BaseEntity;
import com.side.cooktime.domain.userstorage.model.UserStorage;
import jakarta.persistence.*;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Table(name = "member")
@Inheritance(strategy = InheritanceType.JOINED)
public abstract class Member extends BaseEntity {

    @Embedded
    protected Email email;
    @Embedded
    protected Password password;
    @Embedded
    protected Name name;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", updatable = false)
    protected Role role;

    //TODO: 소셜로그인 추가 적용시 테이블 분리
    protected String provider;
    protected String providerId;

    @OneToMany(mappedBy = "member", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    private final List<UserStorage> userStorages = new ArrayList<>();

    protected Member(final Role role, final String email, final String password, final String firstName, final String lastName) {
        super();
        this.role = role;
        this.email = new Email(email);
        this.password = new Password(password);
        this.name = new Name(firstName, lastName);
    }

    protected Member(final Role role, final String provider, final String providerId, final String email, final String password, final String firstName, final String lastName) {
        super();
        this.role = role;
        this.provider = provider;
        this.providerId = providerId;
        this.email = new Email(email);
        this.password = new Password(password);
        this.name = new Name(firstName, lastName);
    }

    public String getRoleKey() {
        return role.getKey();
    }

    protected Member() {
        ;
    }
}
