package com.github.highcumontoa.springauthzguardrailsjava.web;

import com.github.highcumontoa.springauthzguardrailsjava.auth.CredentialStore;
import com.github.highcumontoa.springauthzguardrailsjava.auth.RefreshResult;
import com.github.highcumontoa.springauthzguardrailsjava.auth.RefreshTokenService;
import com.github.highcumontoa.springauthzguardrailsjava.auth.TokenService;
import com.github.highcumontoa.springauthzguardrailsjava.auth.UserAccount;
import com.github.highcumontoa.springauthzguardrailsjava.ratelimit.RateLimitDecision;
import com.github.highcumontoa.springauthzguardrailsjava.ratelimit.RateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Optional;

/**
 * 认证端点：登录校验凭据并签发访问令牌 + 续期凭据；续期凭旧续期凭据轮换新凭据并换发访问令牌；
 * 注销使该主体已签发的访问令牌与续期凭据立即失效。
 *
 * 登录与续期两个入口的失败尝试由独立的 authRateLimiter 统计并限流，
 * 与业务接口（/api/**）的限流彼此独立、互不牵连。
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final CredentialStore credentialStore;
    private final TokenService tokenService;
    private final RefreshTokenService refreshTokenService;
    private final RateLimiter authRateLimiter;

    public AuthController(CredentialStore credentialStore, TokenService tokenService,
                          RefreshTokenService refreshTokenService,
                          @Qualifier("authRateLimiter") RateLimiter authRateLimiter) {
        this.credentialStore = credentialStore;
        this.tokenService = tokenService;
        this.refreshTokenService = refreshTokenService;
        this.authRateLimiter = authRateLimiter;
    }

    public record LoginRequest(String username, String password) {
    }

    public record RefreshRequest(String refreshToken) {
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        // 登录入口限流：按用户名统计失败尝试，与业务接口限流相互独立
        String rateKey = "login:" + request.username();
        ResponseEntity<?> limited = checkRateLimit(rateKey, "login");
        if (limited != null) {
            return limited;
        }
        Optional<UserAccount> account = credentialStore.findByUsername(request.username());
        if (account.isEmpty() || !credentialStore.verifyPassword(account.get(), request.password())) {
            // 用户不存在与口令错误返回同一结论，避免账号枚举
            authRateLimiter.recordFailure(rateKey);
            log.info("判定结论: DENIED status=401 reason=BAD_CREDENTIALS username={}", request.username());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(DecisionResponse.denied("BAD_CREDENTIALS", "用户名或口令错误"));
        }
        String token = tokenService.issueToken(account.get().username(), account.get().permissions());
        String refreshToken = refreshTokenService.issueRefreshToken(
                account.get().username(), account.get().permissions());
        log.info("判定结论: ALLOWED reason=LOGIN_OK username={}", request.username());
        return ResponseEntity.ok(Map.of(
                "token", token,
                "refreshToken", refreshToken,
                "subject", account.get().username()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest request, HttpServletRequest http) {
        // 续期入口限流：按来源地址统计失败尝试（凭据可能已被篡改，不可信其声明的主体）
        String rateKey = "refresh:" + http.getRemoteAddr();
        ResponseEntity<?> limited = checkRateLimit(rateKey, "refresh");
        if (limited != null) {
            return limited;
        }
        RefreshResult result = refreshTokenService.rotate(request.refreshToken());
        if (!result.success()) {
            authRateLimiter.recordFailure(rateKey);
            log.info("判定结论: DENIED status=401 reason={} (refresh)", result.failureReason());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(DecisionResponse.denied(result.failureReason().name(),
                            describe(result.failureReason())));
        }
        // 换发访问令牌：权限快照自登录时刻，与原登录主体保持一致，不降权不越权
        String token = tokenService.issueToken(result.subject(), result.permissions());
        log.info("判定结论: ALLOWED reason=REFRESH_OK subject={}", result.subject());
        return ResponseEntity.ok(Map.of(
                "token", token,
                "refreshToken", result.newRefreshToken(),
                "subject", result.subject()));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String header) {
        if (header == null || !header.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(DecisionResponse.denied("TOKEN_MISSING", "未提供访问令牌"));
        }
        String token = header.substring(7).trim();
        var result = tokenService.validate(token);
        if (result.success()) {
            // 主体级撤销：该主体此前签发的访问令牌与续期凭据都立即失效
            tokenService.revokeAllForSubject(result.subject());
            refreshTokenService.revokeAllForSubject(result.subject());
            log.info("判定结论: ALLOWED reason=LOGOUT_OK subject={}", result.subject());
            return ResponseEntity.ok(DecisionResponse.allowed("已注销，该主体全部令牌与续期凭据立即失效"));
        }
        // 令牌本身已失效时也撤销该令牌编号，保证幂等
        tokenService.revoke(token);
        log.info("判定结论: DENIED status=401 reason={} (logout)", result.failureReason());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(DecisionResponse.denied(result.failureReason().name(), "令牌已失效，无需注销"));
    }

    /** 限流检查：超限返回 429 响应，否则返回 null 表示放行。 */
    private ResponseEntity<?> checkRateLimit(String rateKey, String entry) {
        RateLimitDecision rate = authRateLimiter.tryAcquire(rateKey);
        if (rate.allowed()) {
            return null;
        }
        log.info("判定结论: DENIED status=429 reason=RATE_LIMITED entry={} key={}", entry, rateKey);
        return ResponseEntity.status(429)
                .body(DecisionResponse.denied("RATE_LIMITED",
                        entry + " 入口失败尝试过多，" + rate.retryAfterMillis() + "ms 后窗口滚动自动恢复"));
    }

    private static String describe(com.github.highcumontoa.springauthzguardrailsjava.auth.AuthFailureReason reason) {
        return switch (reason) {
            case REFRESH_TOKEN_MISSING -> "未提供续期凭据";
            case REFRESH_TOKEN_TAMPERED -> "续期凭据格式非法或签名不匹配（疑似被篡改）";
            case REFRESH_TOKEN_EXPIRED -> "续期凭据已过期";
            case REFRESH_TOKEN_REVOKED -> "续期凭据已被撤销（注销、已轮换作废或被重复使用）";
            default -> "续期凭据无效";
        };
    }
}
