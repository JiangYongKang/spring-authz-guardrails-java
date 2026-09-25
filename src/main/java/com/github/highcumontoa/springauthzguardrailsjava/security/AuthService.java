package com.github.highcumontoa.springauthzguardrailsjava.security;

import com.github.highcumontoa.springauthzguardrailsjava.config.GuardrailProperties;
import com.github.highcumontoa.springauthzguardrailsjava.domain.UserAccount;
import com.github.highcumontoa.springauthzguardrailsjava.store.UserDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * 认证服务：校验凭据、签发令牌、处理注销，并对同一主体的登录失败进行滑动窗口限流。
 *
 * <p>登录失败与访问限流是两套相互独立的计数器，失败原因（{@link RejectionReason}）
 * 互不掩盖。
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserDirectory userDirectory;
    private final TokenService tokenService;
    private final SlidingWindowRateLimiter loginFailures;

    public AuthService(UserDirectory userDirectory,
                       TokenService tokenService,
                       GuardrailProperties properties) {
        this.userDirectory = userDirectory;
        this.tokenService = tokenService;
        this.loginFailures = new SlidingWindowRateLimiter(
                properties.getRateLimit().getLoginFailureLimit(),
                properties.getRateLimit().getLoginWindowSeconds());
    }

    /**
     * 凭据校验并签发令牌。
     *
     * @throws GuardrailRejectionException 失败尝试超限或凭据错误，原因可区分
     */
    public TokenService.IssuedToken login(String username, String password) {
        String key = "login:" + username;
        // 先判定失败窗口：即使后续凭据正确，窗口内失败次数超限期间也必须被限制
        if (!loginFailures.isWithinLimit(key)) {
            log.warn("拒绝登录 subject={} reason={} detail=失败尝试已超过滑动窗口阈值",
                    username, RejectionReason.LOGIN_RATE_LIMITED);
            throw new GuardrailRejectionException(RejectionReason.LOGIN_RATE_LIMITED,
                    "登录失败尝试过于频繁，请稍后再试", 429);
        }

        Optional<UserAccount> account = userDirectory.findByUsername(username);
        if (account.isEmpty() || !account.get().getPassword().equals(password)) {
            boolean stillAllowed = loginFailures.recordFailure(key);
            log.warn("拒绝登录 subject={} reason={} detail=用户名或密码错误, 窗口内剩余尝试空间={}",
                    username, RejectionReason.BAD_CREDENTIALS, stillAllowed);
            throw new GuardrailRejectionException(RejectionReason.BAD_CREDENTIALS,
                    "用户名或密码错误", 401);
        }

        loginFailures.reset(key);
        return tokenService.issue(account.get());
    }

    /** 注销：撤销当前令牌；可选撤销该主体全部已签发令牌。 */
    public void logout(UserAccount user, String rawToken, boolean revokeAll) {
        if (revokeAll) {
            tokenService.revokeAll(user.getUsername());
            log.info("注销 subject={} scope=ALL 该主体全部已签发令牌立即失效", user.getUsername());
        } else {
            tokenService.revoke(rawToken);
            log.info("注销 subject={} scope=CURRENT 当前令牌立即失效", user.getUsername());
        }
    }

    /** 供测试重置登录失败计数。 */
    public void resetLoginFailures(String username) {
        loginFailures.reset("login:" + username);
    }
}
