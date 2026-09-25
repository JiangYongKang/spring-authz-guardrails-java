package com.github.highcumontoa.springauthzguardrailsjava.security;

import com.github.highcumontoa.springauthzguardrailsjava.domain.UserAccount;

public record AccessDecision(
        boolean allowed,
        UserAccount user,
        RejectionReason reason,
        String message
) {
    public static AccessDecision permit(UserAccount user) {
        return new AccessDecision(true, user, null, null);
    }

    public static AccessDecision reject(RejectionReason reason, String message) {
        return new AccessDecision(false, null, reason, message);
    }
}
