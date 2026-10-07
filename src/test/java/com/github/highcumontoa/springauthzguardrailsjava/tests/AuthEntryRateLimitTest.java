package com.github.highcumontoa.springauthzguardrailsjava.tests;

import com.github.highcumontoa.springauthzguardrailsjava.ratelimit.RateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 登录与续期入口的失败限流专项测试：
 * 反复失败被统计并限流（429）、窗口推移自动恢复、成功后正常继续、
 * 与业务接口（/api/**）限流彼此独立，且各入口拒绝结论可区分。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "security.token.ttl-seconds=300",
        "security.refresh.ttl-seconds=3600",
        "ratelimit.window-millis=1000",
        "ratelimit.max-requests=3",
        "ratelimit.max-failures=1000",
        "ratelimit.auth.window-millis=1000",
        "ratelimit.auth.max-requests=1000",
        "ratelimit.auth.max-failures=3"
})
class AuthEntryRateLimitTest {

    @TestConfiguration
    static class TestClockConfig {
        static final MutableClock CLOCK = new MutableClock(Instant.parse("2026-09-25T00:00:00Z"));

        @Bean
        @Primary
        Clock mutableClock() {
            return CLOCK;
        }
    }

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    @Autowired
    RateLimiter rateLimiter;

    @Autowired
    @Qualifier("authRateLimiter")
    RateLimiter authRateLimiter;

    private String base;

    @BeforeEach
    void setUp() {
        base = "http://localhost:" + port;
        rateLimiter.reset();
        authRateLimiter.reset();
    }

    // ---------- 登录入口限流 ----------

    @Test
    void repeatedBadLoginsAreRateLimitedThenRecover() {
        // 阈值 max-failures=3：前 4 次失败仍返回 401 BAD_CREDENTIALS（第 4 次失败后计数达 4）
        for (int i = 0; i < 4; i++) {
            ResponseEntity<Map> resp = login("alice", "wrong-" + i);
            assertEquals(401, resp.getStatusCode().value(), "第 " + (i + 1) + " 次失败应返回 401");
            assertEquals("BAD_CREDENTIALS", resp.getBody().get("reason"));
        }
        // 第 5 次：即使口令正确也被限流
        ResponseEntity<Map> limited = login("alice", "alice-pass");
        assertEquals(429, limited.getStatusCode().value());
        assertEquals("RATE_LIMITED", limited.getBody().get("reason"));
        // 限流结论与凭据错误可区分
        assertNotEquals("BAD_CREDENTIALS", limited.getBody().get("reason"));

        // 窗口推移后自动恢复，成功后正常继续
        TestClockConfig.CLOCK.advance(Duration.ofMillis(1001));
        ResponseEntity<Map> ok = login("alice", "alice-pass");
        assertEquals(200, ok.getStatusCode().value(), "窗口滚动后正确口令必须能登录");
        String token = (String) ok.getBody().get("token");
        assertEquals(200, get("/api/resource", token).getStatusCode().value());
    }

    @Test
    void loginRateLimitIsPerUsername() {
        for (int i = 0; i < 5; i++) {
            login("alice", "wrong");
        }
        assertEquals(429, login("alice", "alice-pass").getStatusCode().value());
        // 其它用户的登录入口不受牵连
        assertEquals(200, login("bob", "bob-pass").getStatusCode().value());
    }

    // ---------- 续期入口限流 ----------

    @Test
    void repeatedFailedRefreshesAreRateLimitedThenRecover() {
        String goodRefresh = (String) login("alice", "alice-pass").getBody().get("refreshToken");
        // 前 4 次失败返回 401 REFRESH_TOKEN_TAMPERED
        for (int i = 0; i < 4; i++) {
            ResponseEntity<Map> resp = refresh("bad.refresh.token");
            assertEquals(401, resp.getStatusCode().value(), "第 " + (i + 1) + " 次失败应返回 401");
            assertEquals("REFRESH_TOKEN_TAMPERED", resp.getBody().get("reason"));
        }
        // 第 5 次：即使凭据有效也被限流
        ResponseEntity<Map> limited = refresh(goodRefresh);
        assertEquals(429, limited.getStatusCode().value());
        assertEquals("RATE_LIMITED", limited.getBody().get("reason"));

        // 窗口推移后自动恢复，有效凭据可正常续期
        TestClockConfig.CLOCK.advance(Duration.ofMillis(1001));
        ResponseEntity<Map> ok = refresh(goodRefresh);
        assertEquals(200, ok.getStatusCode().value(), "窗口滚动后有效续期凭据必须能续期");
        String newToken = (String) ok.getBody().get("token");
        assertEquals(200, get("/api/resource", newToken).getStatusCode().value());
    }

    // ---------- 与业务接口限流相互独立 ----------

    @Test
    void authEntryLimitDoesNotAffectApiAccess() {
        // 把登录入口打到限流
        for (int i = 0; i < 5; i++) {
            login("alice", "wrong");
        }
        assertEquals(429, login("alice", "alice-pass").getStatusCode().value());
        // 已登录主体访问业务接口不受认证入口限流影响
        String bobToken = (String) login("bob", "bob-pass").getBody().get("token");
        assertEquals(200, get("/api/resource", bobToken).getStatusCode().value());
    }

    @Test
    void apiLimitDoesNotAffectAuthEntries() {
        String token = (String) login("carol", "carol-pass").getBody().get("token");
        // 业务接口限流阈值 max-requests=3：打满后第 4 次 429
        for (int i = 0; i < 3; i++) {
            assertEquals(200, get("/api/resource", token).getStatusCode().value());
        }
        ResponseEntity<Map> limited = get("/api/resource", token);
        assertEquals(429, limited.getStatusCode().value());
        assertEquals("RATE_LIMITED", limited.getBody().get("reason"));
        // 登录与续期入口不受业务接口限流影响
        ResponseEntity<Map> login = login("alice", "alice-pass");
        assertEquals(200, login.getStatusCode().value());
        assertEquals(200, refresh((String) login.getBody().get("refreshToken")).getStatusCode().value());
    }

    // ---------- 辅助方法 ----------

    private ResponseEntity<Map> login(String username, String password) {
        return rest.postForEntity(base + "/auth/login",
                Map.of("username", username, "password", password), Map.class);
    }

    private ResponseEntity<Map> refresh(String refreshToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return rest.exchange(base + "/auth/refresh", HttpMethod.POST,
                new HttpEntity<>(Map.of("refreshToken", refreshToken), headers), Map.class);
    }

    private ResponseEntity<Map> get(String path, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return rest.exchange(base + path, HttpMethod.GET, new HttpEntity<>("{}", headers), Map.class);
    }
}
