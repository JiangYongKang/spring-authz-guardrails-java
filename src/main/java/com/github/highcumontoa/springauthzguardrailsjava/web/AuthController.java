package com.github.highcumontoa.springauthzguardrailsjava.web;

import com.github.highcumontoa.springauthzguardrailsjava.auth.CredentialStore;
import com.github.highcumontoa.springauthzguardrailsjava.auth.TokenService;
import com.github.highcumontoa.springauthzguardrailsjava.auth.UserAccount;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 * 认证端点：登录校验凭据并签发令牌；注销使该主体已签发的令牌立即失效。
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final CredentialStore credentialStore;
    private final TokenService tokenService;

    public AuthController(CredentialStore credentialStore, TokenService tokenService) {
        this.credentialStore = credentialStore;
        this.tokenService = tokenService;
    }

    public record LoginRequest(String username, String password) {
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        Optional<UserAccount> account = credentialStore.findByUsername(request.username());
        if (account.isEmpty() || !credentialStore.verifyPassword(account.get(), request.password())) {
            // 用户不存在与口令错误返回同一结论，避免账号枚举
            log.info("判定结论: DENIED status=401 reason=BAD_CREDENTIALS username={}", request.username());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(DecisionResponse.denied("BAD_CREDENTIALS", "用户名或口令错误"));
        }
        String token = tokenService.issueToken(account.get().username(), account.get().permissions());
        log.info("判定结论: ALLOWED reason=LOGIN_OK username={}", request.username());
        return ResponseEntity.ok(Map.of("token", token, "subject", account.get().username()));
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
            // 主体级撤销：该主体此前签发的所有令牌立即失效
            tokenService.revokeAllForSubject(result.subject());
            log.info("判定结论: ALLOWED reason=LOGOUT_OK subject={}", result.subject());
            return ResponseEntity.ok(DecisionResponse.allowed("已注销，该主体全部令牌立即失效"));
        }
        // 令牌本身已失效时也撤销该令牌编号，保证幂等
        tokenService.revoke(token);
        log.info("判定结论: DENIED status=401 reason={} (logout)", result.failureReason());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(DecisionResponse.denied(result.failureReason().name(), "令牌已失效，无需注销"));
    }
}
