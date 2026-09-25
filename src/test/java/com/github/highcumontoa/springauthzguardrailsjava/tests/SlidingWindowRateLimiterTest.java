package com.github.highcumontoa.springauthzguardrailsjava.tests;

import com.github.highcumontoa.springauthzguardrailsjava.security.SlidingWindowRateLimiter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class SlidingWindowRateLimiterTest {

    @Test
    @DisplayName("达到阈值后拒绝，窗口推移后自动恢复")
    void limitAndRecovery() {
        // 窗口长度 10 秒（注入毫秒时间）
        SlidingWindowRateLimiter limiter = new SlidingWindowRateLimiter(3, 10);

        long t0 = 1_000L;
        assertThat(limiter.tryAcquireAt("k", t0)).isTrue();
        assertThat(limiter.tryAcquireAt("k", t0 + 1_000)).isTrue();
        assertThat(limiter.tryAcquireAt("k", t0 + 2_000)).isTrue();
        // 窗口内第 4 次必须被限制
        assertThat(limiter.tryAcquireAt("k", t0 + 3_000)).isFalse();

        // 最早一条记录滑出窗口后恢复一个配额
        assertThat(limiter.tryAcquireAt("k", t0 + 10_001)).isTrue();
        // 此时窗口内为 t0+1000, t0+2000, t0+10001，再次到达阈值
        assertThat(limiter.tryAcquireAt("k", t0 + 10_500)).isFalse();

        // 全部记录滑出后完全恢复
        assertThat(limiter.tryAcquireAt("k", t0 + 30_000)).isTrue();
    }

    @Test
    @DisplayName("不同 key 的计数器相互独立")
    void keysAreIndependent() {
        SlidingWindowRateLimiter limiter = new SlidingWindowRateLimiter(1, 10);

        assertThat(limiter.tryAcquireAt("a", 0)).isTrue();
        assertThat(limiter.tryAcquireAt("a", 1)).isFalse();
        assertThat(limiter.tryAcquireAt("b", 1)).isTrue();
    }

    @Test
    @DisplayName("并发请求下成功数量严格等于阈值，判定保持一致")
    void concurrentAcquiresNeverExceedLimit() throws InterruptedException {
        SlidingWindowRateLimiter limiter = new SlidingWindowRateLimiter(20, 60);
        int threads = 100;
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    if (limiter.tryAcquire("shared-key")) {
                        allowed.incrementAndGet();
                    } else {
                        rejected.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertThat(done.await(10, TimeUnit.SECONDS)).isTrue();
        pool.shutdown();

        assertThat(allowed.get()).isEqualTo(20);
        assertThat(rejected.get()).isEqualTo(80);
        assertThat(allowed.get() + rejected.get()).isEqualTo(threads);
    }

    @Test
    @DisplayName("reset 后计数清零")
    void resetClearsWindow() {
        SlidingWindowRateLimiter limiter = new SlidingWindowRateLimiter(1, 10);
        assertThat(limiter.tryAcquireAt("k", 0)).isTrue();
        assertThat(limiter.tryAcquireAt("k", 1)).isFalse();

        limiter.reset("k");

        assertThat(limiter.tryAcquireAt("k", 2)).isTrue();
    }
}
