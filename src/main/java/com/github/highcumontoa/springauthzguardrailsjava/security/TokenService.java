package com.github.highcumontoa.springauthzguardrailsjava.security;

import com.github.highcumontoa.springauthzguardrailsjava.domain.UserAccount;

public interface TokenService {

    IssuedToken issue(UserAccount user);

    AccessDecision validate(String token);

    void revoke(String token);

    void revokeAll(String username);

    record IssuedToken(String token, long expiresAtEpochSeconds) {
    }
}
