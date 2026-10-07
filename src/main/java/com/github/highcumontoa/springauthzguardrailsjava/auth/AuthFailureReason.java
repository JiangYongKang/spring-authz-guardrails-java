package com.github.highcumontoa.springauthzguardrailsjava.auth;

/**
 * 认证失败原因，各原因必须可区分。
 */
public enum AuthFailureReason {
    /** 未提供令牌 */
    TOKEN_MISSING,
    /** 令牌格式非法或签名不匹配（被篡改） */
    TOKEN_TAMPERED,
    /** 令牌已过期 */
    TOKEN_EXPIRED,
    /** 令牌已被撤销（注销或主动失效） */
    TOKEN_REVOKED,
    /** 未提供续期凭据 */
    REFRESH_TOKEN_MISSING,
    /** 续期凭据格式非法或签名不匹配（被篡改） */
    REFRESH_TOKEN_TAMPERED,
    /** 续期凭据已过期 */
    REFRESH_TOKEN_EXPIRED,
    /** 续期凭据已被撤销（注销、已轮换作废或被重复使用） */
    REFRESH_TOKEN_REVOKED
}
