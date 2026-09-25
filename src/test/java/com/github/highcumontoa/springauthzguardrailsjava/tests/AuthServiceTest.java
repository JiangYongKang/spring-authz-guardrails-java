package com.github.highcumontoa.springauthzguardrailsjava.tests;

import com.github.highcumontoa.springauthzguardrailsjava.config.GuardrailProperties;
import com.github.highcumontoa.springauthzguardrailsjava.security.AuthService;
import com.github.highcumontoa.springauthzguardrailsjava.security.GuardrailRejectionException;
import com.github.highcumontoa.springauthzguardrailsjava.security.HmacTokenService;
import com.github.highcumontoa.springauthzguardrailsjava.security.RejectionReason;
import com.github.highcumontoa.springauthzguardrailsjava.security.TokenService;
import com.github.highcumontoa.springauthzguardrailsjava.store.UserDirectory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthServiceTest {

    private AuthService authService;
    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        GuardrailProperties properties = new GuardrailProperties();
        // 窗口内允许 3 次失败
        properties.getRateLimit().setLoginFailureLimit(3);
        properties.getRateLimit().setLoginWindowSeconds(60);
        tokenService = new HmacTokenService(properties, new UserDirectory());
        authService = new AuthService(new UserDirectory(), tokenService, properties);
    }

    @Test
    @DisplayName("正确凭据签发令牌")
    void loginSucceedsWithCorrectCredentials() {
        TokenService.IssuedToken issued = authService.login("alice", "password-alice");

        assertThat(issued.token()).contains(".");
        assertThat(tokenService.validate(issued.token()).allowed()).isTrue();
    }

    @Test
    @DisplayName("错误密码 -> BAD_CREDENTIALS(401)，与限流(429) 可区分")
    void badCredentialsAreDistinctFromRateLimit() {
        assertThatThrownBy(() -> authService.login("alice", "wrong"))
                .isInstanceOfSatisfying(GuardrailRejectionException.class, ex -> {
                    assertThat(ex.getReason()).isEqualTo(RejectionReason.BAD_CREDENTIALS);
                    assertThat(ex.getHttpStatus()).isEqualTo(401);
                });
    }

    @Test
    @DisplayName("失败次数达到阈值后 -> LOGIN_RATE_LIMITED(429)，即使密码正确也被限制")
    void loginRateLimitedAfterThreshold() {
        for (int i = 0; i < 3; i++) {
            assertThatThrownBy(() -> authService.login("bob", "wrong"))
                    .extracting("reason")
                    .isEqualTo(RejectionReason.BAD_CREDENTIALS);
        }

        // 第 4 次即使给出正确密码，仍因失败窗口被限流
        assertThatThrownBy(() -> authService.login("bob", "password-bob"))
                .isInstanceOfSatisfying(GuardrailRejectionException.class, ex -> {
                    assertThat(ex.getReason()).isEqualTo(RejectionReason.LOGIN_RATE_LIMITED);
                    assertThat(ex.getHttpStatus()).isEqualTo(429);
                });
    }

    @Test
    @DisplayName("成功登录会重置该主体的失败计数")
    void successfulLoginResetsFailureCounter() {
        assertThatThrownBy(() -> authService.login("admin", "wrong"))
                .isInstanceOf(GuardrailRejectionException.class);

        TokenService.IssuedToken issued = authService.login("admin", "password-admin");
        assertThat(issued).isNotNull();

        // 重置后重新允许 3 次失败（这里再连续 2 次错误仍应是 BAD_CREDENTIALS 而非限流）
        for (int i = 0; i < 2; i++) {
            assertThatThrownBy(() -> authService.login("admin", "wrong"))
                    .extracting("reason")
                    .isEqualTo(RejectionReason.BAD_CREDENTIALS);
        }
    }

    @Test
    @DisplayName("登录限流按用户名独立统计")
    void rateLimitIsPerSubject() {
        for (int i = 0; i < 3; i++) {
            assertThatThrownBy(() -> authService.login("bob", "wrong"))
                    .isInstanceOf(GuardrailRejectionException.class);
        }

        // bob 被限流，不影响 alice 正常登录
        assertThat(authService.login("alice", "password-alice")).isNotNull();
    }
}
