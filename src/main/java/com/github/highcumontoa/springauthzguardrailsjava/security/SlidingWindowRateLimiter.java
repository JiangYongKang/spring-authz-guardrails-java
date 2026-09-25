package com.github.highcumontoa.springauthzguardrailsjava.security;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 基于滑动时间窗口的本地限流器。
 *
 * <p>每个 key 维护一个时间戳队列，仅保留窗口内的访问记录；
 * 队列长度达到阈值后拒绝新请求，随着窗口推移旧记录过期，限流自动恢复。
 * 所有按 key 的统计与判定都在同一把锁内完成，保证并发请求下结论一致。
 */
public class SlidingWindowRateLimiter {

    private final int limit;
    private final long windowMillis;
    private final Map<String, Deque<Long>> windows = new ConcurrentHashMap<>();

    public SlidingWindowRateLimiter(int limit, long windowSeconds) {
        if (limit <= 0) {
            throw new IllegalArgumentException("限流阈值必须大于 0");
        }
        this.limit = limit;
        this.windowMillis = windowSeconds * 1000L;
    }

    /**
     * 尝试占用一次配额。
     *
     * @return true 表示放行，false 表示已超过窗口阈值
     */
    public boolean tryAcquire(String key) {
        return tryAcquireAt(key, System.currentTimeMillis());
    }

    /** 注入时间的重载，便于测试窗口恢复。 */
    public boolean tryAcquireAt(String key, long nowMillis) {
        Deque<Long> window = windows.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (window) {
            evictExpired(window, nowMillis);
            if (window.size() >= limit) {
                return false;
            }
            window.addLast(nowMillis);
            return true;
        }
    }

    /** 仅检查当前窗口是否还有配额，不占用配额。 */
    public boolean isWithinLimit(String key) {
        return isWithinLimitAt(key, System.currentTimeMillis());
    }

    public boolean isWithinLimitAt(String key, long nowMillis) {
        Deque<Long> window = windows.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (window) {
            evictExpired(window, nowMillis);
            return window.size() < limit;
        }
    }

    /** 记录一次失败尝试（不占用成功请求的配额），达到阈值时返回 false。 */
    public boolean recordFailure(String key) {
        return recordFailureAt(key, System.currentTimeMillis());
    }

    public boolean recordFailureAt(String key, long nowMillis) {
        Deque<Long> window = windows.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (window) {
            evictExpired(window, nowMillis);
            window.addLast(nowMillis);
            return window.size() < limit;
        }
    }

    private void evictExpired(Deque<Long> window, long nowMillis) {
        while (!window.isEmpty() && nowMillis - window.peekFirst() >= windowMillis) {
            window.pollFirst();
        }
    }

    public void reset(String key) {
        Deque<Long> window = windows.get(key);
        if (window != null) {
            synchronized (window) {
                window.clear();
            }
        }
    }
}
