package com.github.highcumontoa.springauthzguardrailsjava.web;

import com.github.highcumontoa.springauthzguardrailsjava.auth.CredentialStore;
import com.github.highcumontoa.springauthzguardrailsjava.auth.RefreshFailureReason;
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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * 认证端点：
 *  - POST /auth/login  校验凭据，签发访问令牌 + 续期凭据；
 *  - POST /auth/refresh 凭续期凭据原子轮换，换发新的访问令牌 + 新的续期凭据（旧凭据当场作废）；
 *  - POST /auth/logout 主体级注销，此前签发的访问令牌与续期凭据立即全部失效。
 *
 * 登录与续期入口使用与业务接口相互独立的认证限流器（按用户名 / 来源地址统计失败尝试），
 * 各入口被限流的结论分别为 LOGIN_RATE_LIMITED / REFRESH_RATE_LIMITED，互不掩盖。
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final CredentialStore credentialStore;
    private final TokenService tokenService;
    private final RefreshTokenService refreshTokenService;
    private final RateLimiter authRateLimiter;

    public AuthController(CredentialStore credentialStore,
                          TokenService tokenService,
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
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletRequest http) {
        String username = request.username() == null ? "" : request.username();
        String rateKey = "login:" + username;
        RateLimitDecision gate = authRateLimiter.tryAcquire(rateKey);
        if (!gate.allowed()) {
            return deniedLoginLimited(http, username, gate.retryAfterMillis());
        }
        Optional<UserAccount> account = credentialStore.findByUsername(request.username());
        if (account.isEmpty() || !credentialStore.verifyPassword(account.get(), request.password())) {
            // 用户不存在与口令错误返回同一结论，避免账号枚举
            authRateLimiter.recordFailure(rateKey);
            log.info("判定结论: DENIED status=401 reason=BAD_CREDENTIALS username={} ip={}",
                    username, http.getRemoteAddr());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(DecisionResponse.denied("BAD_CREDENTIALS", "用户名或口令错误"));
        }
        // 成功后清空该主体此前的失败统计，立即恢复正常
        authRateLimiter.reset(rateKey);
        UserAccount acc = account.get();
        long generation = tokenService.currentGeneration(acc.username());
        Map<String, Object> tokens = issuePair(acc, generation);
        log.info("判定结论: ALLOWED reason=LOGIN_OK username={}", acc.username());
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest request, HttpServletRequest http) {
        String rateKey = "refresh-ip:" + http.getRemoteAddr();
        RateLimitDecision gate = authRateLimiter.tryAcquire(rateKey);
        if (!gate.allowed()) {
            return deniedRefreshLimited(http, gate.retryAfterMillis());
        }
        String credential = request == null ? null : request.refreshToken();
        RefreshResult rotated = refreshTokenService.rotate(credential);
        if (!rotated.success()) {
            authRateLimiter.recordFailure(rateKey);
            RefreshFailureReason reason = rotated.failureReason();
            log.info("判定结论: DENIED status=401 reason={} detail={} ip={}",
                    reason.name(), describeRefresh(reason), http.getRemoteAddr());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(DecisionResponse.denied(reason.name(), describeRefresh(reason)));
        }
        Optional<UserAccount> account = credentialStore.findByUsername(rotated.subject());
        if (account.isEmpty()) {
            // 主体已不存在：凭据虽通过自检，也不得换发令牌；按撤销拒绝
            authRateLimiter.recordFailure(rateKey);
            log.info("判定结论: DENIED status=401 reason=REFRESH_REVOKED detail=主体不存在 subject={}",
                    rotated.subject());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(DecisionResponse.denied(RefreshFailureReason.REFRESH_REVOKED.name(),
                            "续期凭据对应主体已不可用"));
        }
        // 成功后清空该来源此前的失败统计
        authRateLimiter.reset(rateKey);
        // 新访问令牌的权限取自账号库当前权限：与原登录主体一致，不降权也不越权
        Map<String, Object> tokens = issuePair(account.get(), rotated.generation());
        log.info("判定结论: ALLOWED reason=REFRESH_OK subject={} generation={}",
                rotated.subject(), rotated.generation());
        return ResponseEntity.ok(tokens);
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
            // 主体级撤销：访问令牌与续期凭据的注销代号同时前进，此前凭据全部立即失效；
            // 代号只增不减，之后重新登录拿到的新凭据携带新代号，立即可用且旧凭据不复活。
            tokenService.revokeAllForSubject(result.subject());
            refreshTokenService.revokeAllForSubject(result.subject());
            log.info("判定结论: ALLOWED reason=LOGOUT_OK subject={}", result.subject());
            return ResponseEntity.ok(DecisionResponse.allowed("已注销，该主体全部访问令牌与续期凭据立即失效"));
        }
        // 令牌本身已失效时也撤销该令牌编号，保证幂等
        tokenService.revoke(token);
        log.info("判定结论: DENIED status=401 reason={} (logout)", result.failureReason());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(DecisionResponse.denied(result.failureReason().name(), "令牌已失效，无需注销"));
    }

    /** 换发一对令牌；访问令牌与续期凭据携带同一注销代号。 */
    private Map<String, Object> issuePair(UserAccount account, long generation) {
        String accessToken = tokenService.issueToken(account.username(), account.permissions(), generation);
        String refreshToken = refreshTokenService.issueToken(account.username(), generation);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", accessToken);
        body.put("refreshToken", refreshToken);
        body.put("subject", account.username());
        return body;
    }

    private ResponseEntity<?> deniedLoginLimited(HttpServletRequest http, String username, long retryAfter) {
        String detail = "登录失败尝试超过阈值，" + retryAfter + "ms 后窗口滚动自动恢复";
        log.info("判定结论: DENIED status=429 reason=LOGIN_RATE_LIMITED detail={} username={} ip={}",
                detail, username, http.getRemoteAddr());
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(DecisionResponse.denied("LOGIN_RATE_LIMITED", detail));
    }

    private ResponseEntity<?> deniedRefreshLimited(HttpServletRequest http, long retryAfter) {
        String detail = "续期失败尝试超过阈值，" + retryAfter + "ms 后窗口滚动自动恢复";
        log.info("判定结论: DENIED status=429 reason=REFRESH_RATE_LIMITED detail={} ip={}",
                detail, http.getRemoteAddr());
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(DecisionResponse.denied("REFRESH_RATE_LIMITED", detail));
    }

    private static String describeRefresh(RefreshFailureReason reason) {
        return switch (reason) {
            case REFRESH_MISSING -> "未提供续期凭据";
            case REFRESH_TAMPERED -> "续期凭据格式非法或签名不匹配（疑似被篡改，或误将访问令牌用作续期凭据）";
            case REFRESH_EXPIRED -> "续期凭据已过期";
            case REFRESH_REVOKED -> "续期凭据已被撤销（主体注销）";
            case REFRESH_USED -> "续期凭据已被轮换使用（旧凭据重放）";
        };
    }
}
