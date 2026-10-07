package com.github.highcumontoa.springauthzguardrailsjava;

import com.github.highcumontoa.springauthzguardrailsjava.ratelimit.RateLimiter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * 通用基础设施 Bean。时钟独立成 Bean 便于测试注入固定/可变时钟。
 */
@Configuration
public class AppConfig {

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }

    /**
     * 认证入口（登录/续期）专用限流器：与业务接口限流器相互独立、状态互不牵连。
     */
    @Bean
    public RateLimiter authRateLimiter(@Value("${ratelimit.auth.window-millis:60000}") long windowMillis,
                                       @Value("${ratelimit.auth.max-requests:100}") long maxRequests,
                                       @Value("${ratelimit.auth.max-failures:5}") long maxFailures,
                                       Clock clock) {
        return new RateLimiter(windowMillis, maxRequests, maxFailures, clock);
    }
}
