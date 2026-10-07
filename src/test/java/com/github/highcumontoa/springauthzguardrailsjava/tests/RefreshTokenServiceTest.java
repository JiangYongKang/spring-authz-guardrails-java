package com.github.highcumontoa.springauthzguardrailsjava.tests;

import com.github.highcumontoa.springauthzguardrailsjava.auth.RefreshFailureReason;
import com.github.highcumontoa.springauthzguardrailsjava.auth.RefreshResult;
import com.github.highcumontoa.springauthzguardrailsjava.auth.RefreshTokenService;
import com.github.highcumontoa.springauthzguardrailsjava.auth.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

class RefreshTokenServiceTest {

    private static final byte[] SECRET = "refresh-secret-key-0123456789abcd".getBytes(StandardCharsets.UTF_8);

    private MutableClock clock;
    private RefreshTokenService refresh;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-10-01T00:00:00Z"));
        refresh = new RefreshTokenService(SECRET, 3600, clock);
    }

    @Test
    void rotateSucceedsAndReturnsSubjectAndGeneration() {
        String rft = refresh.issueToken("alice", 0);
        RefreshResult result = refresh.rotate(rft);
        assertTrue(result.success());
        assertEquals("alice", result.subject());
        assertEquals(0L, result.generation());
    }

    @Test
    void missingCredentialRejected() {
        RefreshResult result = refresh.rotate(null);
        assertFalse(result.success());
        assertEquals(RefreshFailureReason.REFRESH_MISSING, result.failureReason());
    }

    @Test
    void malformedCredentialRejectedAsTampered() {
        assertEquals(RefreshFailureReason.REFRESH_TAMPERED, refresh.rotate("not-a-token").failureReason());
    }

    @Test
    void wrongSignatureRejectedAsTampered() {
        RefreshTokenService attacker = new RefreshTokenService(
                "attacker-key-0000000000000000000".getBytes(StandardCharsets.UTF_8), 3600, clock);
        String forged = attacker.issueToken("alice", 0);
        assertEquals(RefreshFailureReason.REFRESH_TAMPERED, refresh.rotate(forged).failureReason());
    }

    @Test
    void accessTokenCannotBeUsedAsRefreshCredential() {
        // 访问令牌没有 kind=refresh 声明，即使签名密钥不同也会被拒；此处用同密钥模拟“声明不符”
        TokenService access = new TokenService(SECRET, 300, clock);
        String accessToken = access.issueToken("alice", Set.of("RESOURCE_READ"), 0);
        assertEquals(RefreshFailureReason.REFRESH_TAMPERED, refresh.rotate(accessToken).failureReason());
    }

    @Test
    void expiredCredentialRejectedWithDistinctReason() {
        String rft = refresh.issueToken("alice", 0);
        clock.advance(Duration.ofSeconds(3601));
        assertEquals(RefreshFailureReason.REFRESH_EXPIRED, refresh.rotate(rft).failureReason());
    }

    @Test
    void oldCredentialRejectedAfterRevocationAndReLoginDoesNotReviveIt() {
        String old = refresh.issueToken("alice", 0);
        // 注销：代号前进
        refresh.revokeAllForSubject("alice");
        assertEquals(1L, refresh.currentGeneration("alice"));
        assertEquals(RefreshFailureReason.REFRESH_REVOKED, refresh.inspect(old).failureReason());
        // 重新登录拿到的是新一代号的凭据，旧凭据依然不可用（不会因重新登录复活）
        String afterRelogin = refresh.issueToken("alice", refresh.currentGeneration("alice"));
        assertEquals(RefreshFailureReason.REFRESH_REVOKED, refresh.rotate(old).failureReason());
        assertTrue(refresh.rotate(afterRelogin).success());
    }

    @Test
    void rotatedCredentialIsOneTimeOnly() {
        String rft = refresh.issueToken("alice", 0);
        assertTrue(refresh.rotate(rft).success());
        // 旧凭据重放必须被拒绝，且原因可区分
        assertEquals(RefreshFailureReason.REFRESH_USED, refresh.rotate(rft).failureReason());
    }

    @Test
    void concurrentReplayOfSameCredentialSucceedsAtMostOnce() throws Exception {
        String rft = refresh.issueToken("alice", 0);
        int threads = 24;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Callable<Boolean>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> refresh.rotate(rft).success());
        }
        List<Future<Boolean>> results = pool.invokeAll(tasks);
        pool.shutdown();
        long success = 0;
        for (Future<Boolean> f : results) {
            if (f.get()) {
                success++;
            }
        }
        assertEquals(1, success, "并发轮换同一凭据至多一次成功");
    }

    @Test
    void otherSubjectUnaffectedByRevocation() {
        String alice = refresh.issueToken("alice", 0);
        String bob = refresh.issueToken("bob", 0);
        refresh.revokeAllForSubject("alice");
        assertEquals(RefreshFailureReason.REFRESH_REVOKED, refresh.inspect(alice).failureReason());
        assertTrue(refresh.inspect(bob).success());
    }

    @Test
    void tamperedPayloadRejected() {
        String rft = refresh.issueToken("alice", 0);
        String[] parts = rft.split("\\.");
        // 篡改 payload：把代号改成旧值之外的内容，签名不变 -> 签名校验即失败
        String forged = "{\"sub\":\"alice\",\"kind\":\"refresh\",\"iat\":1,\"exp\":9999999999,\"gen\":99,\"jti\":\"x\"}";
        String tampered = parts[0] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(forged.getBytes(StandardCharsets.UTF_8))
                + "." + parts[2];
        assertEquals(RefreshFailureReason.REFRESH_TAMPERED, refresh.rotate(tampered).failureReason());
    }
}
