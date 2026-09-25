package com.github.highcumontoa.springauthzguardrailsjava.tests;

import com.github.highcumontoa.springauthzguardrailsjava.auth.AuthFailureReason;
import com.github.highcumontoa.springauthzguardrailsjava.auth.AuthResult;
import com.github.highcumontoa.springauthzguardrailsjava.auth.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class TokenServiceTest {

    private static final byte[] SECRET = "test-secret-key-0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    private MutableClock clock;
    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-09-25T00:00:00Z"));
        tokenService = new TokenService(SECRET, 60, clock);
    }

    @Test
    void validTokenPasses() {
        String token = tokenService.issueToken("alice", Set.of("RESOURCE_READ"));
        AuthResult result = tokenService.validate(token);
        assertTrue(result.success());
        assertEquals("alice", result.subject());
        assertEquals(Set.of("RESOURCE_READ"), result.permissions());
    }

    @Test
    void missingTokenRejected() {
        AuthResult result = tokenService.validate(null);
        assertFalse(result.success());
        assertEquals(AuthFailureReason.TOKEN_MISSING, result.failureReason());
    }

    @Test
    void expiredTokenRejectedWithDistinctReason() {
        String token = tokenService.issueToken("alice", Set.of());
        clock.advance(Duration.ofSeconds(61));
        AuthResult result = tokenService.validate(token);
        assertFalse(result.success());
        assertEquals(AuthFailureReason.TOKEN_EXPIRED, result.failureReason());
    }

    @Test
    void tamperedPayloadRejected() {
        String token = tokenService.issueToken("alice", Set.of("RESOURCE_READ"));
        String[] parts = token.split("\\.");
        // 篡改 payload：伪造权限，但签名不变
        String forged = "{\"sub\":\"alice\",\"perms\":\"ADMIN_OPERATE\",\"iat\":1,\"exp\":9999999999,\"jti\":\"x\"}";
        String tampered = parts[0] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(forged.getBytes(StandardCharsets.UTF_8))
                + "." + parts[2];
        AuthResult result = tokenService.validate(tampered);
        assertFalse(result.success());
        assertEquals(AuthFailureReason.TOKEN_TAMPERED, result.failureReason());
    }

    @Test
    void tokenSignedWithWrongKeyRejected() {
        TokenService attacker = new TokenService(
                "attacker-key-0000000000000000000".getBytes(StandardCharsets.UTF_8), 60, clock);
        String forged = attacker.issueToken("alice", Set.of("ADMIN_OPERATE"));
        AuthResult result = tokenService.validate(forged);
        assertFalse(result.success());
        assertEquals(AuthFailureReason.TOKEN_TAMPERED, result.failureReason());
    }

    @Test
    void malformedTokenRejected() {
        AuthResult result = tokenService.validate("not-a-token");
        assertFalse(result.success());
        assertEquals(AuthFailureReason.TOKEN_TAMPERED, result.failureReason());
    }

    @Test
    void revokedTokenRejectedImmediately() {
        String token = tokenService.issueToken("alice", Set.of());
        tokenService.revoke(token);
        AuthResult result = tokenService.validate(token);
        assertFalse(result.success());
        assertEquals(AuthFailureReason.TOKEN_REVOKED, result.failureReason());
    }

    @Test
    void logoutInvalidatesAllPreviouslyIssuedTokens() {
        String t1 = tokenService.issueToken("alice", Set.of());
        String t2 = tokenService.issueToken("alice", Set.of());
        tokenService.revokeAllForSubject("alice");
        assertEquals(AuthFailureReason.TOKEN_REVOKED, tokenService.validate(t1).failureReason());
        assertEquals(AuthFailureReason.TOKEN_REVOKED, tokenService.validate(t2).failureReason());
        // 注销后新签发的令牌不受影响
        clock.advance(Duration.ofSeconds(1));
        String t3 = tokenService.issueToken("alice", Set.of());
        assertTrue(tokenService.validate(t3).success());
    }

    @Test
    void otherSubjectUnaffectedByRevocation() {
        String alice = tokenService.issueToken("alice", Set.of());
        String bob = tokenService.issueToken("bob", Set.of());
        tokenService.revokeAllForSubject("alice");
        assertFalse(tokenService.validate(alice).success());
        assertTrue(tokenService.validate(bob).success());
    }
}
