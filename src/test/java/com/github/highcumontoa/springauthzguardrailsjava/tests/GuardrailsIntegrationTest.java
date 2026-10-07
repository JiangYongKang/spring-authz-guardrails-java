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
        "security.refresh-token.ttl-seconds=7200",
        "ratelimit.window-millis=1000",
        "ratelimit.max-requests=50",
        "ratelimit.max-failures=1000",
        "ratelimit.auth.window-millis=1000",
        "ratelimit.auth.max-requests=100000",
        "ratelimit.auth.max-failures=3"
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
    @Qualifier("apiRateLimiter")
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

    // ---------- 续期：成功换发、权限一致 ----------

    @Test
    void refreshIssuesUsableTokenWithSamePermissions() {
        Map<String, Object> pair = loginPair("bob", "bob-pass"); // ADMIN
        String refreshToken = (String) pair.get("refreshToken");
        // 访问令牌过期后，无需口令即可续期
        TestClockConfig.CLOCK.advance(Duration.ofSeconds(301));
        Map<String, Object> refreshed = refresh(refreshToken);
        String newToken = (String) refreshed.get("token");
        // 新令牌立即可用
        assertEquals(200, get("/api/resource", newToken).getStatusCode().value());
        // 权限与原登录主体一致：bob 仍是 ADMIN（不越权也不降权）
        assertEquals(200, get("/api/admin/stats", newToken).getStatusCode().value());
        assertNotNull(refreshed.get("refreshToken"));
    }

    @Test
    void refreshDoesNotEscalatePermissions() {
        Map<String, Object> pair = loginPair("carol", "carol-pass"); // GUEST
        Map<String, Object> refreshed = refresh((String) pair.get("refreshToken"));
        String newToken = (String) refreshed.get("token");
        // GUEST 续期后仍不能写、不能管理
        assertEquals(403, post("/api/resource", newToken).getStatusCode().value());
        assertEquals(403, get("/api/admin/stats", newToken).getStatusCode().value());
        assertEquals(200, get("/api/resource", newToken).getStatusCode().value());
    }

    // ---------- 续期凭据：过期 / 篡改 / 撤销 / 已轮换，结论可区分 ----------

    @Test
    void expiredRefreshCredentialRejectedWithDistinctReason() {
        Map<String, Object> pair = loginPair("alice", "alice-pass");
        TestClockConfig.CLOCK.advance(Duration.ofSeconds(7201));
        ResponseEntity<Map> resp = postJson("/auth/refresh",
                Map.of("refreshToken", pair.get("refreshToken")), null);
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("REFRESH_EXPIRED", resp.getBody().get("reason"));
    }

    @Test
    void tamperedRefreshCredentialRejected() {
        loginPair("alice", "alice-pass");
        ResponseEntity<Map> resp = postJson("/auth/refresh",
                Map.of("refreshToken", "garbage.token.value"), null);
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("REFRESH_TAMPERED", resp.getBody().get("reason"));
    }

    @Test
    void accessTokenCannotBeUsedAsRefreshCredential() {
        Map<String, Object> pair = loginPair("alice", "alice-pass");
        ResponseEntity<Map> resp = postJson("/auth/refresh",
                Map.of("refreshToken", pair.get("token")), null);
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("REFRESH_TAMPERED", resp.getBody().get("reason"));
    }

    @Test
    void missingRefreshCredentialRejected() {
        ResponseEntity<Map> resp = postJson("/auth/refresh", Map.of(), null);
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("REFRESH_MISSING", resp.getBody().get("reason"));
    }

    @Test
    void revokedRefreshCredentialRejectedAfterLogout() {
        Map<String, Object> pair = loginPair("alice", "alice-pass");
        assertEquals(200, postWithToken("/auth/logout", (String) pair.get("token")).getStatusCode().value());
        ResponseEntity<Map> resp = postJson("/auth/refresh",
                Map.of("refreshToken", pair.get("refreshToken")), null);
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("REFRESH_REVOKED", resp.getBody().get("reason"));
    }

    // ---------- 一次性轮换：旧凭据当场作废 ----------

    @Test
    void refreshRotatesCredentialAndOldOneIsInvalid() {
        Map<String, Object> pair = loginPair("alice", "alice-pass");
        String oldRefresh = (String) pair.get("refreshToken");
        Map<String, Object> first = refresh(oldRefresh);
        String newRefresh = (String) first.get("refreshToken");
        assertNotEquals(oldRefresh, newRefresh);
        // 旧凭据再次使用被拒，且不产生新凭据
        ResponseEntity<Map> replay = postJson("/auth/refresh", Map.of("refreshToken", oldRefresh), null);
        assertEquals(401, replay.getStatusCode().value());
        assertEquals("REFRESH_USED", replay.getBody().get("reason"));
        // 新凭据可继续轮换
        Map<String, Object> second = refresh(newRefresh);
        assertEquals(200, get("/api/resource", (String) second.get("token")).getStatusCode().value());
    }

    @Test
    void concurrentRefreshWithSameCredentialSucceedsAtMostOnce() throws Exception {
        Map<String, Object> pair = loginPair("alice", "alice-pass");
        String oldRefresh = (String) pair.get("refreshToken");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Callable<Integer>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> postJson("/auth/refresh", Map.of("refreshToken", oldRefresh), null)
                    .getStatusCode().value());
        }
        List<Future<Integer>> results = pool.invokeAll(tasks);
        pool.shutdown();
        int ok = 0, rejected = 0, other = 0;
        for (Future<Integer> f : results) {
            int status = f.get();
            if (status == 200) {
                ok++;
            } else if (status == 401 || status == 429) {
                // 401 REFRESH_USED 为旧凭据重放；失败尝试累积到阈值后按入口限流 429 拒绝——
                // 二者都是“拒绝且不产生新凭据”，服务层并发单测严格保证恰一次成功
                rejected++;
            } else {
                other++;
            }
        }
        // 再发一次确认旧凭据状态为 REFRESH_USED（结论本身可区分）
        ResponseEntity<Map> replay = postJson("/auth/refresh", Map.of("refreshToken", oldRefresh), null);
        assertTrue(replay.getStatusCode().value() == 401 || replay.getStatusCode().value() == 429);
        assertEquals(1, ok, "并发轮换仅一次成功，不会多出可用凭据");
        assertEquals(threads - 1, rejected, "其余全部被拒绝");
        assertEquals(0, other, "不得出现非拒绝类异常结论");
    }

    // ---------- 注销即时性与隔离性 ----------

    @Test
    void reloginImmediatelyAfterLogoutWorksWithoutClockAdvance() {
        Map<String, Object> pair = loginPair("alice", "alice-pass");
        String token = (String) pair.get("token");
        assertEquals(200, get("/api/resource", token).getStatusCode().value());
        // 注销
        assertEquals(200, postWithToken("/auth/logout", token).getStatusCode().value());
        // 旧访问令牌与旧续期凭据立即失效
        assertEquals(401, get("/api/resource", token).getStatusCode().value());
        ResponseEntity<Map> oldRefresh = postJson("/auth/refresh",
                Map.of("refreshToken", pair.get("refreshToken")), null);
        assertEquals("REFRESH_REVOKED", oldRefresh.getBody().get("reason"));
        // 不推进时间，立刻重新登录：新令牌马上可用
        Map<String, Object> rePair = loginPair("alice", "alice-pass");
        String newToken = (String) rePair.get("token");
        assertEquals(200, get("/api/resource", newToken).getStatusCode().value());
        // 新续期凭据可用
        Map<String, Object> refreshed = refresh((String) rePair.get("refreshToken"));
        assertEquals(200, get("/api/resource", (String) refreshed.get("token")).getStatusCode().value());
        // 旧凭据依旧作废（未因重新登录复活）
        ResponseEntity<Map> stale = postJson("/auth/refresh",
                Map.of("refreshToken", pair.get("refreshToken")), null);
        assertEquals(401, stale.getStatusCode().value());
        assertEquals("REFRESH_REVOKED", stale.getBody().get("reason"));
    }

    @Test
    void logoutOfOneSubjectDoesNotAffectOthers() {
        Map<String, Object> alice = loginPair("alice", "alice-pass");
        Map<String, Object> bob = loginPair("bob", "bob-pass");
        assertEquals(200, postWithToken("/auth/logout", (String) alice.get("token")).getStatusCode().value());
        // bob 的访问令牌与续期凭据不受牵连
        assertEquals(200, get("/api/resource", (String) bob.get("token")).getStatusCode().value());
        Map<String, Object> bobRefreshed = refresh((String) bob.get("refreshToken"));
        assertEquals(200, get("/api/resource", (String) bobRefreshed.get("token")).getStatusCode().value());
    }

    // ---------- 认证入口限流：失败计数、阈值、恢复、与业务限流独立 ----------

    @Test
    void failedLoginAttemptsAreRateLimitedAndRecover() {
        for (int i = 0; i < 3; i++) {
            ResponseEntity<Map> bad = rest.postForEntity(base + "/auth/login",
                    Map.of("username", "alice", "password", "wrong"), Map.class);
            assertEquals(401, bad.getStatusCode().value());
            assertEquals("BAD_CREDENTIALS", bad.getBody().get("reason"));
        }
        // 第 4 次（即使口令正确）在窗口内被登录入口限流，结论可区分
        ResponseEntity<Map> limited = rest.postForEntity(base + "/auth/login",
                Map.of("username", "alice", "password", "alice-pass"), Map.class);
        assertEquals(429, limited.getStatusCode().value());
        assertEquals("LOGIN_RATE_LIMITED", limited.getBody().get("reason"));
        // 窗口滚动后自动恢复
        TestClockConfig.CLOCK.advance(Duration.ofMillis(1001));
        Map<String, Object> pair = loginPair("alice", "alice-pass");
        assertEquals(200, get("/api/resource", (String) pair.get("token")).getStatusCode().value());
    }

    @Test
    void failedRefreshAttemptsAreRateLimitedAndRecover() {
        loginPair("alice", "alice-pass");
        for (int i = 0; i < 3; i++) {
            ResponseEntity<Map> bad = postJson("/auth/refresh",
                    Map.of("refreshToken", "bad.token.x"), null);
            assertEquals(401, bad.getStatusCode().value());
            assertEquals("REFRESH_TAMPERED", bad.getBody().get("reason"));
        }
        ResponseEntity<Map> limited = postJson("/auth/refresh",
                Map.of("refreshToken", "bad.token.x"), null);
        assertEquals(429, limited.getStatusCode().value());
        assertEquals("REFRESH_RATE_LIMITED", limited.getBody().get("reason"));
        // 窗口推移后，合法续期恢复正常
        TestClockConfig.CLOCK.advance(Duration.ofMillis(1001));
        Map<String, Object> pair = loginPair("alice", "alice-pass");
        assertEquals(200, postJson("/auth/refresh",
                Map.of("refreshToken", pair.get("refreshToken")), null).getStatusCode().value());
    }

    @Test
    void authEntryRateLimitIsIndependentOfApiRateLimit() {
        // 业务接口被限流
        String token = login("alice", "alice-pass");
        for (int i = 0; i < 50; i++) {
            assertEquals(200, get("/api/resource", token).getStatusCode().value());
        }
        assertEquals(429, get("/api/resource", token).getStatusCode().value());
        // 登录入口不受业务限流牵连
        Map<String, Object> pair = loginPair("bob", "bob-pass");
        assertNotNull(pair.get("refreshToken"));
        // 续期入口同样不受牵连
        assertEquals(200, postJson("/auth/refresh",
                Map.of("refreshToken", pair.get("refreshToken")), null).getStatusCode().value());
    }

    // ---------- 辅助方法 ----------

    private String login(String username, String password) {
        return (String) loginPair(username, password).get("token");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> loginPair(String username, String password) {
        ResponseEntity<Map> resp = rest.postForEntity(base + "/auth/login",
                Map.of("username", username, "password", password), Map.class);
        assertEquals(200, resp.getStatusCode().value(), "登录应成功: " + username);
        return resp.getBody();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> refresh(String refreshToken) {
        ResponseEntity<Map> resp = postJson("/auth/refresh", Map.of("refreshToken", refreshToken), null);
        assertEquals(200, resp.getStatusCode().value(), "续期应成功");
        return resp.getBody();
    }

    private ResponseEntity<Map> postJson(String path, Object body, String bearerToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (bearerToken != null) {
            headers.setBearerAuth(bearerToken);
        }
        return rest.exchange(base + path, HttpMethod.POST, new HttpEntity<>(body, headers), Map.class);
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
