package com.github.highcumontoa.springauthzguardrailsjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.springauthzguardrailsjava.security.AuthService;
import com.github.highcumontoa.springauthzguardrailsjava.security.SlidingWindowRateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 端到端集成测试：真实启动 Spring Boot，通过 HTTP 验证
 * 认证、授权、限流三类结论的状态码与 reason 均互不相同。
 * 拒绝请求的判定依据由 GuardrailFilter 以 WARN 日志打印。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GuardrailIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private SlidingWindowRateLimiter accessRateLimiter;

    @Autowired
    private AuthService authService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void resetCounters() {
        for (String user : new String[]{"alice", "bob", "admin"}) {
            accessRateLimiter.reset("access:" + user);
            authService.resetLoginFailures(user);
        }
    }

    private String base() {
        return "http://localhost:" + port;
    }

    private String login(String username, String password) throws Exception {
        ResponseEntity<String> response = restTemplate.postForEntity(
                base() + "/api/auth/login",
                Map.of("username", username, "password", password),
                String.class);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        return objectMapper.readTree(response.getBody()).get("accessToken").asText();
    }

    private ResponseEntity<String> getWithToken(String path, String token) {
        HttpHeaders headers = new HttpHeaders();
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return restTemplate.exchange(base() + path, HttpMethod.GET,
                new HttpEntity<>(headers), String.class);
    }

    @Test
    @DisplayName("正常流程：登录 -> 带令牌访问自身资料 -> 200")
    void happyPath() throws Exception {
        String token = login("alice", "password-alice");

        ResponseEntity<String> response = getWithToken("/api/profile/me", token);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).contains("alice").contains("profile:read");
    }

    @Test
    @DisplayName("错误凭据 -> 401 BAD_CREDENTIALS")
    void badCredentials() {
        ResponseEntity<String> response = restTemplate.postForEntity(
                base() + "/api/auth/login",
                Map.of("username", "alice", "password", "nope"),
                String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getBody()).contains("BAD_CREDENTIALS");
    }

    @Test
    @DisplayName("连续失败超过阈值 -> 429 LOGIN_RATE_LIMITED，与凭据错误可区分")
    void loginFailureRateLimited() {
        for (int i = 0; i < 3; i++) {
            ResponseEntity<String> response = restTemplate.postForEntity(
                    base() + "/api/auth/login",
                    Map.of("username", "bob", "password", "wrong"),
                    String.class);
            assertThat(response.getStatusCode().value()).isEqualTo(401);
            assertThat(response.getBody()).contains("BAD_CREDENTIALS");
        }

        ResponseEntity<String> response = restTemplate.postForEntity(
                base() + "/api/auth/login",
                Map.of("username", "bob", "password", "password-bob"),
                String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(429);
        assertThat(response.getBody()).contains("LOGIN_RATE_LIMITED");
    }

    @Test
    @DisplayName("无令牌访问受保护接口 -> 401 MISSING_TOKEN，与 403 明确区分")
    void missingTokenRejected() {
        ResponseEntity<String> response = getWithToken("/api/profile/me", null);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getBody()).contains("MISSING_TOKEN");
    }

    @Test
    @DisplayName("篡改令牌 -> 401 SIGNATURE_INVALID")
    void tamperedTokenRejected() throws Exception {
        String token = login("alice", "password-alice");
        String tampered = token.substring(0, token.length() - 1)
                + (token.endsWith("a") ? "b" : "a");

        ResponseEntity<String> response = getWithToken("/api/profile/me", tampered);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getBody()).contains("SIGNATURE_INVALID");
    }

    @Test
    @DisplayName("结构损坏的令牌 -> 401 MALFORMED_TOKEN")
    void malformedTokenRejected() throws Exception {
        login("alice", "password-alice");

        ResponseEntity<String> response = getWithToken("/api/profile/me", "garbage-token");

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getBody()).contains("MALFORMED_TOKEN");
    }

    @Test
    @DisplayName("普通用户访问管理接口 -> 403 ACCESS_DENIED，且不产生副作用")
    void forbiddenDoesNotProduceSideEffect() throws Exception {
        String aliceToken = login("alice", "password-alice");

        // GET 越权
        ResponseEntity<String> getResponse = getWithToken("/api/users", aliceToken);
        assertThat(getResponse.getStatusCode().value()).isEqualTo(403);
        assertThat(getResponse.getBody()).contains("ACCESS_DENIED");

        // DELETE 越权：必须在过滤器被拦截，控制器不执行，sideEffectApplied 绝不能出现
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(aliceToken);
        ResponseEntity<String> deleteResponse = restTemplate.exchange(
                base() + "/api/users/bob", HttpMethod.DELETE,
                new HttpEntity<>(headers), String.class);
        assertThat(deleteResponse.getStatusCode().value()).isEqualTo(403);
        assertThat(deleteResponse.getBody()).contains("ACCESS_DENIED");
        assertThat(deleteResponse.getBody()).doesNotContain("sideEffectApplied");
    }

    @Test
    @DisplayName("管理员可访问管理接口 -> 200")
    void adminAccessAllowed() throws Exception {
        String adminToken = login("admin", "password-admin");

        assertThat(getWithToken("/api/admin/ping", adminToken).getStatusCode().value()).isEqualTo(200);
        assertThat(getWithToken("/api/users", adminToken).getStatusCode().value()).isEqualTo(200);
    }

    @Test
    @DisplayName("注销后令牌立即失效 -> 401 TOKEN_REVOKED")
    void logoutRevokesTokenImmediately() throws Exception {
        String token = login("alice", "password-alice");
        assertThat(getWithToken("/api/profile/me", token).getStatusCode().value()).isEqualTo(200);

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        ResponseEntity<String> logoutResponse = restTemplate.exchange(
                base() + "/api/auth/logout", HttpMethod.POST,
                new HttpEntity<>(headers), String.class);
        assertThat(logoutResponse.getStatusCode().value()).isEqualTo(200);

        ResponseEntity<String> after = getWithToken("/api/profile/me", token);
        assertThat(after.getStatusCode().value()).isEqualTo(401);
        assertThat(after.getBody()).contains("TOKEN_REVOKED");
    }

    @Test
    @DisplayName("全部注销(all=true)使该主体所有已签发令牌失效")
    void logoutAllRevokesEveryToken() throws Exception {
        String token1 = login("alice", "password-alice");
        String token2 = login("alice", "password-alice");
        assertThat(getWithToken("/api/profile/me", token1).getStatusCode().value()).isEqualTo(200);
        assertThat(getWithToken("/api/profile/me", token2).getStatusCode().value()).isEqualTo(200);

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token1);
        restTemplate.exchange(base() + "/api/auth/logout?all=true", HttpMethod.POST,
                new HttpEntity<>(headers), String.class);

        assertThat(getWithToken("/api/profile/me", token1).getBody()).contains("TOKEN_REVOKED");
        assertThat(getWithToken("/api/profile/me", token2).getBody()).contains("TOKEN_REVOKED");

        // 重新登录后新令牌可用
        String token3 = login("alice", "password-alice");
        assertThat(getWithToken("/api/profile/me", token3).getStatusCode().value()).isEqualTo(200);
    }

    @Test
    @DisplayName("超过访问阈值 -> 429 ACCESS_RATE_LIMITED；窗口推移后自动恢复")
    void accessRateLimitedThenRecovered() throws Exception {
        String token = login("alice", "password-alice");

        // 阈值为 5：前 5 次放行
        for (int i = 0; i < 5; i++) {
            assertThat(getWithToken("/api/profile/me", token).getStatusCode().value())
                    .isEqualTo(200);
        }
        // 第 6 次被限流，且限流原因不被授权失败掩盖（alice 本有 profile:read 权限）
        ResponseEntity<String> limited = getWithToken("/api/profile/me", token);
        assertThat(limited.getStatusCode().value()).isEqualTo(429);
        assertThat(limited.getBody()).contains("ACCESS_RATE_LIMITED");

        // 被拒绝的请求不占用配额、不会延长窗口；因此从“最后一次成功占用配额的请求”起，
        // 静默等待一个完整窗口（测试配置 2 秒），限流应自动恢复
        Thread.sleep(2_300);
        assertThat(getWithToken("/api/profile/me", token).getStatusCode().value())
                .as("窗口滑过后限流应自动恢复为 200")
                .isEqualTo(200);
    }

    @Test
    @DisplayName("并发请求下限流判定一致：恰好放行阈值数量，其余全部 429")
    void concurrentRequestsHaveConsistentDecision() throws Exception {
        String token = login("admin", "password-admin");
        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(10);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger ok = new AtomicInteger();
        AtomicInteger limited = new AtomicInteger();
        AtomicInteger other = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    int status = getWithToken("/api/profile/me", token).getStatusCode().value();
                    if (status == 200) {
                        ok.incrementAndGet();
                    } else if (status == 429) {
                        limited.incrementAndGet();
                    } else {
                        other.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertThat(done.await(15, TimeUnit.SECONDS)).isTrue();
        pool.shutdown();

        assertThat(other.get()).isZero();
        assertThat(ok.get()).isEqualTo(5);
        assertThat(limited.get()).isEqualTo(threads - 5);
    }

    @Test
    @DisplayName("错误响应体始终携带可区分的 reason 与判定依据 message")
    void errorBodiesAlwaysCarryReason() throws Exception {
        String token = login("alice", "password-alice");

        JsonNode unauthenticated = objectMapper.readTree(
                getWithToken("/api/profile/me", null).getBody());
        assertThat(unauthenticated.get("reason").asText()).isEqualTo("MISSING_TOKEN");
        assertThat(unauthenticated.get("message").asText()).isNotBlank();

        JsonNode forbidden = objectMapper.readTree(
                getWithToken("/api/admin/ping", token).getBody());
        assertThat(forbidden.get("reason").asText()).isEqualTo("ACCESS_DENIED");
        assertThat(forbidden.get("message").asText()).contains("admin:read");
    }
}
