package com.github.highcumontoa.springauthzguardrailsjava.security;

public enum RejectionReason {
    MISSING_TOKEN,
    MALFORMED_TOKEN,
    SIGNATURE_INVALID,
    TOKEN_EXPIRED,
    TOKEN_REVOKED,
    BAD_CREDENTIALS,
    LOGIN_RATE_LIMITED,
    ACCESS_RATE_LIMITED,
    ACCESS_DENIED
}
