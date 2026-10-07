package com.github.highcumontoa.springauthzguardrailsjava.tests;

import com.github.highcumontoa.springauthzguardrailsjava.auth.AuthFailureReason;
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

    private static final byte[] SECRET = "refresh-secret-key-0123456789ab".getBytes(StandardCharsets.UTF_8);

    private MutableClock clock;
    private RefreshTokenService service;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-09-25T00:00:00Z"));
        service = new RefreshTokenService(SECRET, 3600, clock);
    }

    @Test
    void rotateSucceedsAndPreservesPermissions() {
        String rt = service.issueRefreshToken("alice", Set.of("RESOURCE_READ", "RESOURCE_WRITE"));
        RefreshResult result = service.rotate(rt);
        assertTrue(result.success());
        assertEquals("alice", result.subject());
        assertEquals(Set.of("RESOURCE_READ", "RESOURCE_WRITE"), result.permissions());
        assertNotNull(result.newRefreshToken());
        assertNotEquals(rt, result.newRefreshToken(), "轮换必须换发新凭据");
    }

    @Test
    void rotatedOldTokenCannotBeReused() {
        String rt = service.issueRefreshToken("alice", Set.of("RESOURCE_READ"));
        RefreshResult first = service.rotate(rt);
        assertTrue(first.success());
        // 旧凭据当场作废
        RefreshResult reuse = service.rotate(rt);
        assertFalse(reuse.success());
        assertEquals(AuthFailureReason.REFRESH_TOKEN_REVOKED, reuse.failureReason());
        // 新凭据可用，且可继续轮换
        RefreshResult second = service.rotate(first.newRefreshToken());
        assertTrue(second.success());
    }

    @Test
    void expiredRefreshTokenRejected() {
        String rt = service.issueRefreshToken("alice", Set.of());
        clock.advance(Duration.ofSeconds(3601));
        RefreshResult result = service.rotate(rt);
        assertFalse(result.success());
        assertEquals(AuthFailureReason.REFRESH_TOKEN_EXPIRED, result.failureReason());
    }

    @Test
    void tamperedRefreshTokenRejected() {
        String rt = service.issueRefreshToken("alice", Set.of("RESOURCE_READ"));
        String[] parts = rt.split("\\.");
        String forgedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"sub\":\"alice\",\"perms\":\"ADMIN_OPERATE\",\"iat\":1,\"exp\":9999999999,"
                        + "\"jti\":\"x\",\"typ\":\"refresh\",\"se\":0}").getBytes(StandardCharsets.UTF_8));
        String tampered = parts[0] + "." + forgedPayload + "." + parts[2];
        RefreshResult result = service.rotate(tampered);
        assertFalse(result.success());
        assertEquals(AuthFailureReason.REFRESH_TOKEN_TAMPERED, result.failureReason());
    }

    @Test
    void refreshTokenSignedWithWrongKeyRejected() {
        RefreshTokenService attacker = new RefreshTokenService(
                "attacker-key-000000000000000000".getBytes(StandardCharsets.UTF_8), 3600, clock);
        String forged = attacker.issueRefreshToken("alice", Set.of("ADMIN_OPERATE"));
        RefreshResult result = service.rotate(forged);
        assertFalse(result.success());
        assertEquals(AuthFailureReason.REFRESH_TOKEN_TAMPERED, result.failureReason());
    }

    @Test
    void accessTokenCannotBeUsedAsRefreshToken() {
        // 同密钥签发的访问令牌：签名有效但缺少 typ=refresh 声明，必须拒绝
        TokenService accessTokens = new TokenService(SECRET, 3600, clock);
        String accessToken = accessTokens.issueToken("alice", Set.of("RESOURCE_READ"));
        RefreshResult result = service.rotate(accessToken);
        assertFalse(result.success());
        assertEquals(AuthFailureReason.REFRESH_TOKEN_TAMPERED, result.failureReason());
    }

    @Test
    void missingRefreshTokenRejected() {
        assertEquals(AuthFailureReason.REFRESH_TOKEN_MISSING, service.rotate(null).failureReason());
        assertEquals(AuthFailureReason.REFRESH_TOKEN_MISSING, service.rotate("  ").failureReason());
    }

    @Test
    void logoutRevokesRefreshTokensImmediately() {
        String rt1 = service.issueRefreshToken("alice", Set.of());
        String rt2 = service.issueRefreshToken("alice", Set.of());
        service.revokeAllForSubject("alice");
        assertEquals(AuthFailureReason.REFRESH_TOKEN_REVOKED, service.rotate(rt1).failureReason());
        assertEquals(AuthFailureReason.REFRESH_TOKEN_REVOKED, service.rotate(rt2).failureReason());
    }

    @Test
    void reLoginImmediatelyAfterLogoutWorksAndOldTokensStayDead() {
        String oldRt = service.issueRefreshToken("alice", Set.of("RESOURCE_READ"));
        service.revokeAllForSubject("alice");
        // 不推进时钟：紧接着重新登录（模拟同一秒内注销并重登）
        String newRt = service.issueRefreshToken("alice", Set.of("RESOURCE_READ"));
        RefreshResult result = service.rotate(newRt);
        assertTrue(result.success(), "注销后立刻重新登录拿到的新凭据必须立即可用");
        // 已撤销的旧凭据不会因重新登录而复效
        assertEquals(AuthFailureReason.REFRESH_TOKEN_REVOKED, service.rotate(oldRt).failureReason());
    }

    @Test
    void otherSubjectUnaffectedByRevocation() {
        String alice = service.issueRefreshToken("alice", Set.of());
        String bob = service.issueRefreshToken("bob", Set.of());
        service.revokeAllForSubject("alice");
        assertFalse(service.rotate(alice).success());
        assertTrue(service.rotate(bob).success());
    }

    @Test
    void concurrentRotationSucceedsExactlyOnce() throws Exception {
        String rt = service.issueRefreshToken("alice", Set.of("RESOURCE_READ"));
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Callable<RefreshResult>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> service.rotate(rt));
        }
        List<Future<RefreshResult>> results = pool.invokeAll(tasks);
        pool.shutdown();
        int ok = 0, revoked = 0, other = 0;
        String soleNewToken = null;
        for (Future<RefreshResult> f : results) {
            RefreshResult r = f.get();
            if (r.success()) {
                ok++;
                soleNewToken = r.newRefreshToken();
            } else if (r.failureReason() == AuthFailureReason.REFRESH_TOKEN_REVOKED) {
                revoked++;
            } else {
                other++;
            }
        }
        assertEquals(1, ok, "并发轮换同一份旧凭据，最多只能有一次成功");
        assertEquals(threads - 1, revoked, "其余都必须以 REFRESH_TOKEN_REVOKED 拒绝");
        assertEquals(0, other);
        // 不能因此多出来可用的凭据：唯一的新凭据可用，且只能用一次
        assertTrue(service.rotate(soleNewToken).success());
        assertFalse(service.rotate(soleNewToken).success());
    }
}
