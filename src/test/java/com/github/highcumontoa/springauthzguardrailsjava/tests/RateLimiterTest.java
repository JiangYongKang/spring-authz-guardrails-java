package com.github.highcumontoa.springauthzguardrailsjava.tests;

import com.github.highcumontoa.springauthzguardrailsjava.ratelimit.RateLimitDecision;
import com.github.highcumontoa.springauthzguardrailsjava.ratelimit.RateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

class RateLimiterTest {

    private MutableClock clock;
    private RateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-09-25T00:00:00Z"));
        // 窗口 1000ms，每窗口最多 5 次访问、3 次失败
        rateLimiter = new RateLimiter(1000, 5, 3, clock);
    }

    @Test
    void allowsUpToThresholdThenRejects() {
        for (int i = 0; i < 5; i++) {
            assertTrue(rateLimiter.tryAcquire("alice").allowed(), "第 " + (i + 1) + " 次应放行");
        }
        RateLimitDecision sixth = rateLimiter.tryAcquire("alice");
        assertFalse(sixth.allowed());
        assertTrue(sixth.retryAfterMillis() > 0);
    }

    @Test
    void recoversAutomaticallyAfterWindowRolls() {
        for (int i = 0; i < 6; i++) {
            rateLimiter.tryAcquire("alice");
        }
        assertFalse(rateLimiter.tryAcquire("alice").allowed());
        // 窗口推移后自动恢复，无需人工干预
        clock.advance(Duration.ofMillis(1001));
        assertTrue(rateLimiter.tryAcquire("alice").allowed());
    }

    @Test
    void failureAttemptsCountedAndLimited() {
        for (int i = 0; i < 4; i++) {
            rateLimiter.recordFailure("mallory");
        }
        // 失败次数超过阈值（3），即使访问次数未超限也被限制
        assertFalse(rateLimiter.tryAcquire("mallory").allowed());
        clock.advance(Duration.ofMillis(1001));
        assertTrue(rateLimiter.tryAcquire("mallory").allowed());
    }

    @Test
    void subjectsAreIndependent() {
        for (int i = 0; i < 6; i++) {
            rateLimiter.tryAcquire("alice");
        }
        assertFalse(rateLimiter.tryAcquire("alice").allowed());
        assertTrue(rateLimiter.tryAcquire("bob").allowed());
    }

    @Test
    void consistentUnderConcurrency() throws Exception {
        int threads = 20;
        int perThread = 5;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Callable<Boolean>> tasks = new ArrayList<>();
        for (int i = 0; i < threads * perThread; i++) {
            tasks.add(() -> rateLimiter.tryAcquire("shared").allowed());
        }
        List<Future<Boolean>> results = pool.invokeAll(tasks);
        pool.shutdown();
        long allowed = 0;
        for (Future<Boolean> f : results) {
            if (f.get()) {
                allowed++;
            }
        }
        // 无论并发如何交错，放行数必须恰好等于窗口上限
        assertEquals(5, allowed, "并发下放行总数必须恒等于阈值");
    }
}
