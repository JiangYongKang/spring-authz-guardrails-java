package com.github.highcumontoa.springauthzguardrailsjava.ratelimit;

import org.springframework.beans.factory.annotation.Value;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 按主体统计的限流器。
 *
 * 策略：固定窗口计数。每个主体在每个窗口内最多允许 maxRequests 次访问；
 * 失败尝试（认证/授权失败）单独计数，超过 maxFailures 同样触发限制。
 * 窗口随时间推移自动滚动，计数清零即自动恢复。
 * 线程安全：所有状态变更通过 ConcurrentHashMap.compute 原子完成。
 *
 * Bean 由 {@code AppConfig} 声明：业务接口（apiRateLimiter）与认证入口
 * （authRateLimiter：登录/续期）使用相互独立的两个实例，互不牵连。
 */
public class RateLimiter {

    private final long windowMillis;
    private final long maxRequests;
    private final long maxFailures;
    private final Clock clock;

    private final Map<String, WindowState> states = new ConcurrentHashMap<>();

    public RateLimiter(@Value("${ratelimit.window-millis:60000}") long windowMillis,
                       @Value("${ratelimit.max-requests:20}") long maxRequests,
                       @Value("${ratelimit.max-failures:5}") long maxFailures,
                       Clock clock) {
        this.windowMillis = windowMillis;
        this.maxRequests = maxRequests;
        this.maxFailures = maxFailures;
        this.clock = clock;
    }

    /**
     * 尝试为主体获取一次访问额度。每次调用计为一次访问。
     *
     * @param subjectKey 主体标识（已认证主体用用户名，未认证用来源地址等）
     */
    public RateLimitDecision tryAcquire(String subjectKey) {
        long now = clock.millis();
        WindowState state = states.compute(subjectKey, (k, old) -> {
            WindowState s = (old == null || old.isExpired(now, windowMillis)) ? new WindowState(now) : old;
            s.requests++;
            return s;
        });
        // 计数“达到”阈值的下一次调用即拒绝：失败数达到上限时，随后的尝试直接被限流
        if (state.requests > maxRequests || state.failures >= maxFailures) {
            return RateLimitDecision.rejected(state.retryAfterMillis(now, windowMillis));
        }
        return RateLimitDecision.allowed(maxRequests - state.requests);
    }

    /** 记录一次失败尝试（认证失败或授权失败），失败过多同样触发限流。 */
    public void recordFailure(String subjectKey) {
        long now = clock.millis();
        states.compute(subjectKey, (k, old) -> {
            WindowState s = (old == null || old.isExpired(now, windowMillis)) ? new WindowState(now) : old;
            s.failures++;
            return s;
        });
    }

    /** 清空全部统计（测试辅助）。 */
    public void reset() {
        states.clear();
    }

    /** 清空单个主体的统计（成功登录/续期后立即恢复，不再受此前失败计数牵连）。 */
    public void reset(String subjectKey) {
        states.remove(subjectKey);
    }

    /** 单个主体的窗口状态。仅在 map.compute 原子区间内被修改，无需额外同步。 */
    private static final class WindowState {
        private final long windowStart;
        private long requests;
        private long failures;

        WindowState(long windowStart) {
            this.windowStart = windowStart;
        }

        boolean isExpired(long now, long windowMillis) {
            return now - windowStart >= windowMillis;
        }

        long retryAfterMillis(long now, long windowMillis) {
            return Math.max(0, windowStart + windowMillis - now);
        }
    }
}
