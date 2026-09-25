package com.github.highcumontoa.springauthzguardrailsjava.ratelimit;

/**
 * 限流判定结果。
 *
 * @param allowed          是否放行
 * @param remaining        当前窗口剩余额度
 * @param retryAfterMillis 被限制时建议的重试等待毫秒数
 */
public record RateLimitDecision(boolean allowed, long remaining, long retryAfterMillis) {

    public static RateLimitDecision allowed(long remaining) {
        return new RateLimitDecision(true, remaining, 0);
    }

    public static RateLimitDecision rejected(long retryAfterMillis) {
        return new RateLimitDecision(false, 0, retryAfterMillis);
    }
}
