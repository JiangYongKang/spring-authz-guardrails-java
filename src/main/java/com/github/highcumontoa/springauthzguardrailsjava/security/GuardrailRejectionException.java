package com.github.highcumontoa.springauthzguardrailsjava.security;

/**
 * 业务层主动抛出的拒绝异常，携带可区分的 {@link RejectionReason}。
 */
public class GuardrailRejectionException extends RuntimeException {

    private final RejectionReason reason;
    private final int httpStatus;

    public GuardrailRejectionException(RejectionReason reason, String message, int httpStatus) {
        super(message);
        this.reason = reason;
        this.httpStatus = httpStatus;
    }

    public RejectionReason getReason() {
        return reason;
    }

    public int getHttpStatus() {
        return httpStatus;
    }
}
