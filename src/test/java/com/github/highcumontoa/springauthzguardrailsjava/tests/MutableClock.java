package com.github.highcumontoa.springauthzguardrailsjava.tests;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.TemporalAmount;
import java.util.concurrent.atomic.AtomicReference;

/** 测试用可变时钟：可手动推进时间以模拟令牌过期与限流窗口滚动。 */
public class MutableClock extends Clock {

    private final AtomicReference<Instant> now;
    private final ZoneId zone;

    public MutableClock(Instant start) {
        this.now = new AtomicReference<>(start);
        this.zone = ZoneId.of("UTC");
    }

    public void advance(TemporalAmount amount) {
        now.updateAndGet(i -> i.plus(amount));
    }

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return now.get();
    }
}
