package com.github.highcumontoa.springauthzguardrailsjava.auth;

/**
 * 续期凭据校验失败原因。
 * 与访问令牌失败原因（{@link AuthFailureReason}）、限流结论彼此可区分。
 */
public enum RefreshFailureReason {
    /** 未提供续期凭据 */
    REFRESH_MISSING,
    /** 续期凭据格式非法或签名不匹配（被篡改/伪造，或误拿访问令牌当续期凭据） */
    REFRESH_TAMPERED,
    /** 续期凭据已过期 */
    REFRESH_EXPIRED,
    /** 续期凭据已被撤销（主体注销） */
    REFRESH_REVOKED,
    /** 续期凭据已被轮换使用（旧凭据重放，含并发重放） */
    REFRESH_USED
}
