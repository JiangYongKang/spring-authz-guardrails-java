package com.github.highcumontoa.springauthzguardrailsjava.tests;

import com.github.highcumontoa.springauthzguardrailsjava.ratelimit.RateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 全链路集成测试：认证、授权、限流三类拒绝必须可区分，且拒绝请求无副作用。
 * 判定依据由拦截器打印到测试日志（"判定结论: DENIED ... reason=..."）。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "security.token.ttl-seconds=300",
        "ratelimit.window-millis=1000",
        "ratelimit.max-requests=50",
        "ratelimit.max-failures=1000"
})
class GuardrailsIntegrationTest {

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

    private String base;

    @BeforeEach
    void setUp() {
        base = "http://localhost:" + port;
        rateLimiter.reset();
        // 令牌时间戳为秒级：每个用例前推进时钟，保证新签发令牌的 iat 严格晚于
        // 此前任何用例产生的注销时间戳，避免用例间状态串扰
        TestClockConfig.CLOCK.advance(Duration.ofSeconds(2));
    }

    // ---------- 正常情形 ----------

    @Test
    void loginAndAccessResource() {
        String token = login("alice", "alice-pass");
        ResponseEntity<Map> resp = get("/api/resource", token);
        assertEquals(200, resp.getStatusCode().value());
        assertEquals("alice", resp.getBody().get("subject"));
    }

    @Test
    void badCredentialsRejected() {
        ResponseEntity<Map> resp = rest.postForEntity(base + "/auth/login",
                Map.of("username", "alice", "password", "wrong"), Map.class);
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("BAD_CREDENTIALS", resp.getBody().get("reason"));
    }

    // ---------- 认证失败：各原因可区分 ----------

    @Test
    void missingTokenRejected() {
        ResponseEntity<Map> resp = get("/api/resource", null);
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("TOKEN_MISSING", resp.getBody().get("reason"));
    }

    @Test
    void tamperedTokenRejected() {
        String token = login("alice", "alice-pass");
        String[] parts = token.split("\\.");
        String forgedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"alice\",\"perms\":\"ADMIN_OPERATE\",\"iat\":1,\"exp\":9999999999,\"jti\":\"x\"}"
                        .getBytes());
        String tampered = parts[0] + "." + forgedPayload + "." + parts[2];
        ResponseEntity<Map> resp = get("/api/resource", tampered);
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("TOKEN_TAMPERED", resp.getBody().get("reason"));
    }

    @Test
    void expiredTokenRejected() {
        String token = login("alice", "alice-pass");
        TestClockConfig.CLOCK.advance(Duration.ofSeconds(301));
        ResponseEntity<Map> resp = get("/api/resource", token);
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("TOKEN_EXPIRED", resp.getBody().get("reason"));
    }

    @Test
    void logoutInvalidatesTokenImmediately() {
        String token = login("alice", "alice-pass");
        assertEquals(200, get("/api/resource", token).getStatusCode().value());

        ResponseEntity<Map> logout = postWithToken("/auth/logout", token);
        assertEquals(200, logout.getStatusCode().value());

        ResponseEntity<Map> after = get("/api/resource", token);
        assertEquals(401, after.getStatusCode().value());
        assertEquals("TOKEN_REVOKED", after.getBody().get("reason"));
    }

    // ---------- 授权失败：与未认证结论不同，且无副作用 ----------

    @Test
    void unauthenticatedAndForbiddenAreDistinct() {
        ResponseEntity<Map> noAuth = post("/api/resource", null);
        ResponseEntity<Map> forbidden = post("/api/resource", login("carol", "carol-pass"));
        assertEquals(401, noAuth.getStatusCode().value());
        assertEquals("TOKEN_MISSING", noAuth.getBody().get("reason"));
        assertEquals(403, forbidden.getStatusCode().value());
        assertEquals("PERMISSION_DENIED", forbidden.getBody().get("reason"));
        assertNotEquals(noAuth.getBody().get("reason"), forbidden.getBody().get("reason"));
    }

    @Test
    void forbiddenWriteHasNoSideEffect() {
        String carol = login("carol", "carol-pass");
        // GUEST 无 RESOURCE_WRITE 权限，连续越权写
        assertEquals(403, post("/api/resource", carol).getStatusCode().value());
        assertEquals(403, post("/api/resource", carol).getStatusCode().value());
        // carol 自己的写计数恒为 0（越权未产生副作用）
        ResponseEntity<Map> count = get("/api/resource/write-count", carol);
        assertEquals(0, ((Number) count.getBody().get("writeCount")).longValue());
    }

    @Test
    void roleBasedAccess() {
        String alice = login("alice", "alice-pass");   // USER
        String bob = login("bob", "bob-pass");         // ADMIN
        assertEquals(403, get("/api/admin/stats", alice).getStatusCode().value());
        assertEquals(200, get("/api/admin/stats", bob).getStatusCode().value());
        assertEquals(200, post("/api/resource", alice).getStatusCode().value());
    }

    // ---------- 并发一致性 ----------

    @Test
    void concurrentDecisionsAreConsistent() throws Exception {
        String alice = login("alice", "alice-pass");
        String carol = login("carol", "carol-pass");
        ExecutorService pool = Executors.newFixedThreadPool(16);
        List<Callable<Integer>> tasks = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            tasks.add(() -> get("/api/resource", alice).getStatusCode().value());
            tasks.add(() -> post("/api/resource", carol).getStatusCode().value());
        }
        List<Future<Integer>> results = pool.invokeAll(tasks);
        pool.shutdown();
        int ok = 0, forbidden = 0, other = 0;
        for (Future<Integer> f : results) {
            int status = f.get();
            if (status == 200) ok++;
            else if (status == 403) forbidden++;
            else other++;
        }
        assertEquals(10, ok, "合法请求在并发下必须全部放行");
        assertEquals(10, forbidden, "越权请求在并发下必须全部拒绝");
        assertEquals(0, other, "不得出现限流等干扰结论");
        // 并发越权后 carol 的写计数仍为零（越权未产生副作用）
        ResponseEntity<Map> count = get("/api/resource/write-count", carol);
        assertEquals(0, ((Number) count.getBody().get("writeCount")).longValue());
    }

    // ---------- 限流：触发、可区分、自动恢复 ----------

    @Test
    void rateLimitTriggersAndRecovers() {
        String token = login("alice", "alice-pass");
        for (int i = 0; i < 50; i++) {
            assertEquals(200, get("/api/resource", token).getStatusCode().value(), "第 " + (i + 1) + " 次应放行");
        }
        ResponseEntity<Map> limited = get("/api/resource", token);
        assertEquals(429, limited.getStatusCode().value());
        assertEquals("RATE_LIMITED", limited.getBody().get("reason"));
        // 限流结论与认证/授权失败可区分
        assertNotEquals("TOKEN_EXPIRED", limited.getBody().get("reason"));
        assertNotEquals("PERMISSION_DENIED", limited.getBody().get("reason"));
        // 窗口推移后自动恢复
        TestClockConfig.CLOCK.advance(Duration.ofMillis(1001));
        assertEquals(200, get("/api/resource", token).getStatusCode().value());
    }

    @Test
    void rateLimitDoesNotMaskAuthFailure() {
        // 先制造认证失败记录，但未超失败阈值时，认证失败原因仍须原样返回
        ResponseEntity<Map> resp = get("/api/resource", "bad.token.here");
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("TOKEN_TAMPERED", resp.getBody().get("reason"));
    }

    // ---------- 辅助方法 ----------

    private String login(String username, String password) {
        ResponseEntity<Map> resp = rest.postForEntity(base + "/auth/login",
                Map.of("username", username, "password", password), Map.class);
        assertEquals(200, resp.getStatusCode().value(), "登录应成功: " + username);
        return (String) resp.getBody().get("token");
    }

    private ResponseEntity<Map> get(String path, String token) {
        return exchange(path, HttpMethod.GET, token);
    }

    private ResponseEntity<Map> post(String path, String token) {
        return exchange(path, HttpMethod.POST, token);
    }

    private ResponseEntity<Map> postWithToken(String path, String token) {
        return exchange(path, HttpMethod.POST, token);
    }

    private ResponseEntity<Map> exchange(String path, HttpMethod method, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return rest.exchange(base + path, method, new HttpEntity<>("{}", headers), Map.class);
    }
}
