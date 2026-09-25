package com.github.highcumontoa.springauthzguardrailsjava.auth;

/**
 * 令牌校验结果：要么成功并携带主体信息，要么失败并携带可区分的原因。
 */
public record AuthResult(boolean success, String subject, java.util.Set<String> permissions,
                         AuthFailureReason failureReason) {

    public static AuthResult ok(String subject, java.util.Set<String> permissions) {
        return new AuthResult(true, subject, permissions, null);
    }

    public static AuthResult fail(AuthFailureReason reason) {
        return new AuthResult(false, null, java.util.Set.of(), reason);
    }
}
