package com.github.highcumontoa.springauthzguardrailsjava.auth;

/**
 * 续期（轮换）结果：成功则携带主体与当前注销代号，失败则携带可区分的原因。
 */
public record RefreshResult(boolean success, String subject, long generation,
                            RefreshFailureReason failureReason) {

    public static RefreshResult ok(String subject, long generation) {
        return new RefreshResult(true, subject, generation, null);
    }

    public static RefreshResult fail(RefreshFailureReason reason) {
        return new RefreshResult(false, null, -1L, reason);
    }
}
