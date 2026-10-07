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
 * 会话续期全链路集成测试：续期成功/过期/篡改/撤销、一次性与并发轮换、
 * 注销即时性与注销后立刻重新登录可用、跨主体隔离、各失败结论可区分。
 * 本类将认证入口限流阈值调高，专注会话生命周期；限流专项见 AuthEntryRateLimitTest。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "security.token.ttl-seconds=300",
        "security.refresh.ttl-seconds=3600",
        "ratelimit.window-millis=1000",
        "ratelimit.max-requests=50",
        "ratelimit.max-failures=1000",
        "ratelimit.auth.window-millis=1000",
        "ratelimit.auth.max-requests=1000",
        "ratelimit.auth.max-failures=1000"
})
class RefreshFlowIntegrationTest {

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

    // ---------- 续期成功 ----------

    @Test
    void loginReturnsRefreshTokenAndRefreshSucceeds() {
        Map<String, String> session = login("alice", "alice-pass");
        assertNotNull(session.get("refreshToken"), "登录必须同时签发续期凭据");

        ResponseEntity<Map> refreshed = refresh(session.get("refreshToken"));
        assertEquals(200, refreshed.getStatusCode().value());
        String newToken = (String) refreshed.getBody().get("token");
        String newRefresh = (String) refreshed.getBody().get("refreshToken");
        assertNotNull(newToken);
        assertNotNull(newRefresh);
        assertNotEquals(session.get("refreshToken"), newRefresh, "每次续期必须换发新续期凭据");

        // 新访问令牌立即可用
        ResponseEntity<Map> resp = get("/api/resource", newToken);
        assertEquals(200, resp.getStatusCode().value());
        assertEquals("alice", resp.getBody().get("subject"));
    }

    @Test
    void refreshedTokenKeepsOriginalPermissionsWithoutDemotionOrEscalation() {
        // alice(USER)：续期后写权限保留，不降权
        Map<String, String> alice = login("alice", "alice-pass");
        String aliceToken = (String) refresh(alice.get("refreshToken")).getBody().get("token");
        assertEquals(200, post("/api/resource", aliceToken).getStatusCode().value());
        // 但未拥有的权限不会凭空出现
        assertEquals(403, get("/api/admin/stats", aliceToken).getStatusCode().value());

        // carol(GUEST)：续期后仍然越权拒绝，不越权
        Map<String, String> carol = login("carol", "carol-pass");
        String carolToken = (String) refresh(carol.get("refreshToken")).getBody().get("token");
        assertEquals(200, get("/api/resource", carolToken).getStatusCode().value());
        ResponseEntity<Map> write = post("/api/resource", carolToken);
        assertEquals(403, write.getStatusCode().value());
        assertEquals("PERMISSION_DENIED", write.getBody().get("reason"));
    }

    @Test
    void refreshWorksWhenAccessTokenExpiringOrJustExpired() {
        Map<String, String> session = login("alice", "alice-pass");
        // 访问令牌刚过期不久（300s TTL，推进 301s），续期凭据（3600s）仍有效
        TestClockConfig.CLOCK.advance(Duration.ofSeconds(301));
        ResponseEntity<Map> expired = get("/api/resource", session.get("token"));
        assertEquals("TOKEN_EXPIRED", expired.getBody().get("reason"));

        ResponseEntity<Map> refreshed = refresh(session.get("refreshToken"));
        assertEquals(200, refreshed.getStatusCode().value(), "访问令牌过期后凭续期凭据仍可换新令牌");
        String newToken = (String) refreshed.getBody().get("token");
        assertEquals(200, get("/api/resource", newToken).getStatusCode().value());
    }

    // ---------- 续期失败：各原因可区分 ----------

    @Test
    void expiredRefreshTokenRejectedWithDistinctReason() {
        Map<String, String> session = login("alice", "alice-pass");
        TestClockConfig.CLOCK.advance(Duration.ofSeconds(3601));
        ResponseEntity<Map> resp = refresh(session.get("refreshToken"));
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("REFRESH_TOKEN_EXPIRED", resp.getBody().get("reason"));
    }

    @Test
    void tamperedRefreshTokenRejectedWithDistinctReason() {
        Map<String, String> session = login("alice", "alice-pass");
        String[] parts = session.get("refreshToken").split("\\.");
        // 篡改 payload：伪造 ADMIN 权限与超长有效期
        String forgedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"sub\":\"alice\",\"perms\":\"ADMIN_OPERATE\",\"iat\":1,\"exp\":9999999999,"
                        + "\"jti\":\"x\",\"typ\":\"refresh\",\"se\":0}").getBytes());
        String tampered = parts[0] + "." + forgedPayload + "." + parts[2];
        ResponseEntity<Map> resp = refresh(tampered);
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("REFRESH_TOKEN_TAMPERED", resp.getBody().get("reason"));
    }

    @Test
    void accessTokenCannotBeUsedAsRefreshToken() {
        Map<String, String> session = login("alice", "alice-pass");
        ResponseEntity<Map> resp = refresh(session.get("token"));
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("REFRESH_TOKEN_TAMPERED", resp.getBody().get("reason"));
    }

    @Test
    void missingRefreshTokenRejectedWithDistinctReason() {
        ResponseEntity<Map> resp = rest.postForEntity(base + "/auth/refresh",
                Map.of(), Map.class);
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("REFRESH_TOKEN_MISSING", resp.getBody().get("reason"));
    }

    @Test
    void refreshFailureReasonsDistinctFromOtherDenials() {
        Map<String, String> session = login("alice", "alice-pass");
        // 续期凭据过期 vs 访问令牌过期 vs 未认证 vs 无权限：结论两两可区分
        TestClockConfig.CLOCK.advance(Duration.ofSeconds(3601));
        String refreshExpired = (String) refresh(session.get("refreshToken")).getBody().get("reason");
        String accessExpired = (String) get("/api/resource", session.get("token")).getBody().get("reason");
        String missing = (String) get("/api/resource", null).getBody().get("reason");
        assertEquals("REFRESH_TOKEN_EXPIRED", refreshExpired);
        assertEquals("TOKEN_EXPIRED", accessExpired);
        assertEquals("TOKEN_MISSING", missing);
        assertNotEquals(refreshExpired, accessExpired);
        assertNotEquals(refreshExpired, missing);
    }

    // ---------- 轮换：一次性与并发 ----------

    @Test
    void rotationIsOneTimeUse() {
        Map<String, String> session = login("alice", "alice-pass");
        ResponseEntity<Map> first = refresh(session.get("refreshToken"));
        assertEquals(200, first.getStatusCode().value());
        // 旧凭据当场作废
        ResponseEntity<Map> reuse = refresh(session.get("refreshToken"));
        assertEquals(401, reuse.getStatusCode().value());
        assertEquals("REFRESH_TOKEN_REVOKED", reuse.getBody().get("reason"));
        // 新凭据可继续轮换
        String newRefresh = (String) first.getBody().get("refreshToken");
        assertEquals(200, refresh(newRefresh).getStatusCode().value());
    }

    @Test
    void concurrentRotationSucceedsExactlyOnce() throws Exception {
        Map<String, String> session = login("alice", "alice-pass");
        String rt = session.get("refreshToken");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Callable<ResponseEntity<Map>>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> refresh(rt));
        }
        List<Future<ResponseEntity<Map>>> results = pool.invokeAll(tasks);
        pool.shutdown();
        int ok = 0, revoked = 0, other = 0;
        String soleNewRefresh = null;
        for (Future<ResponseEntity<Map>> f : results) {
            ResponseEntity<Map> resp = f.get();
            if (resp.getStatusCode().value() == 200) {
                ok++;
                soleNewRefresh = (String) resp.getBody().get("refreshToken");
            } else if ("REFRESH_TOKEN_REVOKED".equals(resp.getBody().get("reason"))) {
                revoked++;
            } else {
                other++;
            }
        }
        assertEquals(1, ok, "同一份旧凭据并发续期，最多只能有一次成功");
        assertEquals(threads - 1, revoked, "其余都必须以 REFRESH_TOKEN_REVOKED 拒绝");
        assertEquals(0, other, "不得出现限流等干扰结论");
        // 不多出可用凭据：唯一的新凭据只能用一次
        assertEquals(200, refresh(soleNewRefresh).getStatusCode().value());
        assertEquals(401, refresh(soleNewRefresh).getStatusCode().value());
    }

    // ---------- 注销：即时性、隔离性、重登可用 ----------

    @Test
    void logoutInvalidatesAccessAndRefreshTokensImmediately() {
        Map<String, String> session = login("alice", "alice-pass");
        assertEquals(200, get("/api/resource", session.get("token")).getStatusCode().value());

        ResponseEntity<Map> logout = postWithToken("/auth/logout", session.get("token"));
        assertEquals(200, logout.getStatusCode().value());

        // 访问令牌与续期凭据同时失效，且原因可区分
        ResponseEntity<Map> apiAfter = get("/api/resource", session.get("token"));
        assertEquals(401, apiAfter.getStatusCode().value());
        assertEquals("TOKEN_REVOKED", apiAfter.getBody().get("reason"));
        ResponseEntity<Map> refreshAfter = refresh(session.get("refreshToken"));
        assertEquals(401, refreshAfter.getStatusCode().value());
        assertEquals("REFRESH_TOKEN_REVOKED", refreshAfter.getBody().get("reason"));
    }

    @Test
    void reLoginImmediatelyAfterLogoutWorksAndRevokedStaysRevoked() {
        Map<String, String> oldSession = login("alice", "alice-pass");
        assertEquals(200, postWithToken("/auth/logout", oldSession.get("token")).getStatusCode().value());

        // 不推进时钟：注销刚完成立刻重新登录
        Map<String, String> newSession = login("alice", "alice-pass");
        assertEquals(200, get("/api/resource", newSession.get("token")).getStatusCode().value(),
                "注销后立刻重新登录拿到的新令牌必须立即可用");
        assertEquals(200, refresh(newSession.get("refreshToken")).getStatusCode().value(),
                "新续期凭据必须立即可用");

        // 已撤销的旧凭据不会因重新登录而复效
        assertEquals("TOKEN_REVOKED", get("/api/resource", oldSession.get("token")).getBody().get("reason"));
        assertEquals("REFRESH_TOKEN_REVOKED",
                refresh(oldSession.get("refreshToken")).getBody().get("reason"));
    }

    @Test
    void logoutOfOneSubjectDoesNotAffectOthers() {
        Map<String, String> alice = login("alice", "alice-pass");
        Map<String, String> bob = login("bob", "bob-pass");
        assertEquals(200, postWithToken("/auth/logout", alice.get("token")).getStatusCode().value());

        assertEquals(200, get("/api/resource", bob.get("token")).getStatusCode().value());
        assertEquals(200, refresh(bob.get("refreshToken")).getStatusCode().value());
        assertEquals(401, get("/api/resource", alice.get("token")).getStatusCode().value());
        assertEquals(401, refresh(alice.get("refreshToken")).getStatusCode().value());
    }

    // ---------- 辅助方法 ----------

    private Map<String, String> login(String username, String password) {
        ResponseEntity<Map> resp = rest.postForEntity(base + "/auth/login",
                Map.of("username", username, "password", password), Map.class);
        assertEquals(200, resp.getStatusCode().value(), "登录应成功: " + username);
        return Map.of(
                "token", (String) resp.getBody().get("token"),
                "refreshToken", (String) resp.getBody().get("refreshToken"));
    }

    private ResponseEntity<Map> refresh(String refreshToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return rest.exchange(base + "/auth/refresh", HttpMethod.POST,
                new HttpEntity<>(Map.of("refreshToken", refreshToken), headers), Map.class);
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
