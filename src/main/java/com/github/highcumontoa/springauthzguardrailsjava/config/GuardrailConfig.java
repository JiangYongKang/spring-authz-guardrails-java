package com.github.highcumontoa.springauthzguardrailsjava.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.springauthzguardrailsjava.security.AuthorizationRules;
import com.github.highcumontoa.springauthzguardrailsjava.security.GuardrailFilter;
import com.github.highcumontoa.springauthzguardrailsjava.security.SlidingWindowRateLimiter;
import com.github.highcumontoa.springauthzguardrailsjava.security.TokenService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
@EnableConfigurationProperties(GuardrailProperties.class)
public class GuardrailConfig {

    @Bean
    public SlidingWindowRateLimiter accessRateLimiter(GuardrailProperties properties) {
        return new SlidingWindowRateLimiter(
                properties.getRateLimit().getAccessLimit(),
                properties.getRateLimit().getWindowSeconds());
    }

    @Bean
    public FilterRegistrationBean<GuardrailFilter> guardrailFilterRegistration(
            TokenService tokenService,
            SlidingWindowRateLimiter accessRateLimiter,
            AuthorizationRules authorizationRules,
            ObjectMapper objectMapper) {
        GuardrailFilter filter = new GuardrailFilter(
                tokenService, accessRateLimiter, authorizationRules, objectMapper);
        FilterRegistrationBean<GuardrailFilter> registration = new FilterRegistrationBean<>(filter);
        registration.addUrlPatterns("/api/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return registration;
    }
}
