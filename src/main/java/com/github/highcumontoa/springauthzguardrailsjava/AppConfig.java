package com.github.highcumontoa.springauthzguardrailsjava;

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
}
