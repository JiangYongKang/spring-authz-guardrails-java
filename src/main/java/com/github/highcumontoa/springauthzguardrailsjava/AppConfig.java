package com.github.highcumontoa.springauthzguardrailsjava;

import com.github.highcumontoa.springauthzguardrailsjava.ratelimit.RateLimiter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * 通用基础设施 Bean。时钟独立成 Bean 便于测试注入固定/可变时钟。
 *
 * 限流器分为两个相互独立的实例：
 *  - apiRateLimiter：已登录主体访问 /api/** 业务接口；
 *  - authRateLimiter：/auth/login 与 /auth/refresh 两个认证入口的失败尝试。
 * 二者窗口与计数完全隔离，任一入口被限都不牵连另一入口。
 */
@Configuration
public class AppConfig {

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }

    @Bean
    public RateLimiter apiRateLimiter(
            @Value("${ratelimit.window-millis:60000}") long windowMillis,
            @Value("${ratelimit.max-requests:20}") long maxRequests,
            @Value("${ratelimit.max-failures:5}") long maxFailures,
            Clock clock) {
        return new RateLimiter(windowMillis, maxRequests, maxFailures, clock);
    }

    @Bean
    public RateLimiter authRateLimiter(
            @Value("${ratelimit.auth.window-millis:60000}") long windowMillis,
            @Value("${ratelimit.auth.max-requests:200}") long maxRequests,
            @Value("${ratelimit.auth.max-failures:5}") long maxFailures,
            Clock clock) {
        return new RateLimiter(windowMillis, maxRequests, maxFailures, clock);
    }
}
