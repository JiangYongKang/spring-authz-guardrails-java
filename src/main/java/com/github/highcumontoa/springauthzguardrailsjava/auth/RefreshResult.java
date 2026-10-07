package com.github.highcumontoa.springauthzguardrailsjava.auth;

import java.util.Set;

/**
 * 续期结果：成功时携带主体、权限与轮换后的新续期凭据；失败时携带可区分的原因。
 */
public record RefreshResult(boolean success, String subject, Set<String> permissions,
                            String newRefreshToken, AuthFailureReason failureReason) {

    public static RefreshResult ok(String subject, Set<String> permissions, String newRefreshToken) {
        return new RefreshResult(true, subject, permissions, newRefreshToken, null);
    }

    public static RefreshResult fail(AuthFailureReason reason) {
        return new RefreshResult(false, null, Set.of(), null, reason);
    }
}
