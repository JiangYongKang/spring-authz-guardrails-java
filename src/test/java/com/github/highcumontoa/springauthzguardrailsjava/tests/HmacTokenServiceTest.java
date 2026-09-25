package com.github.highcumontoa.springauthzguardrailsjava.tests;

import com.github.highcumontoa.springauthzguardrailsjava.config.GuardrailProperties;
import com.github.highcumontoa.springauthzguardrailsjava.domain.UserAccount;
import com.github.highcumontoa.springauthzguardrailsjava.security.AccessDecision;
import com.github.highcumontoa.springauthzguardrailsjava.security.HmacTokenService;
import com.github.highcumontoa.springauthzguardrailsjava.security.RejectionReason;
import com.github.highcumontoa.springauthzguardrailsjava.security.TokenService;
import com.github.highcumontoa.springauthzguardrailsjava.store.UserDirectory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 令牌签发/校验/撤销单元测试。每次拒绝的判定依据由 AccessDecision.reason 区分，
 * 运行时可在日志中看到拒绝依据。
 */
class HmacTokenServiceTest {

    private HmacTokenService tokenService;
    private UserAccount alice;

    @BeforeEach
    void setUp() {
        GuardrailProperties properties = new GuardrailProperties();
        properties.getToken().setTtlSeconds(60);
        tokenService = new HmacTokenService(properties, new UserDirectory());
        alice = new UserAccount("alice", "password-alice",
                Set.of("USER"), Set.of("profile:read"));
    }

    @Test
    @DisplayName("正常签发的令牌可通过校验并还原主体")
    void validTokenIsAccepted() {
        TokenService.IssuedToken issued = tokenService.issue(alice);

        AccessDecision decision = tokenService.validate(issued.token());

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.user()).isNotNull();
        assertThat(decision.user().getUsername()).isEqualTo("alice");
    }

    @Test
    @DisplayName("令牌缺失 -> MISSING_TOKEN")
    void missingToken() {
        AccessDecision decision = tokenService.validate(null);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo(RejectionReason.MISSING_TOKEN);
    }

    @Test
    @DisplayName("令牌格式损坏 -> MALFORMED_TOKEN，与签名错误区分")
    void malformedToken() {
        AccessDecision decision = tokenService.validate("not-a-valid-token");

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo(RejectionReason.MALFORMED_TOKEN);
    }

    @Test
    @DisplayName("令牌载荷被篡改 -> SIGNATURE_INVALID")
    void tamperedPayloadIsRejected() {
        TokenService.IssuedToken issued = tokenService.issue(alice);
        // 翻转 payload 最后一个字符，保持“两段式”结构
        String payload = issued.token().substring(0, issued.token().lastIndexOf('.'));
        String signature = issued.token().substring(issued.token().lastIndexOf('.') + 1);
        char last = payload.charAt(payload.length() - 1);
        String flipped = payload.substring(0, payload.length() - 1) + (last == 'A' ? 'B' : 'A');
        String tampered = flipped + "." + signature;

        AccessDecision decision = tokenService.validate(tampered);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo(RejectionReason.SIGNATURE_INVALID);
    }

    @Test
    @DisplayName("签名段被篡改 -> SIGNATURE_INVALID")
    void tamperedSignatureIsRejected() {
        TokenService.IssuedToken issued = tokenService.issue(alice);
        String tampered = issued.token().substring(0, issued.token().lastIndexOf('.') + 1) + "deadbeef";

        AccessDecision decision = tokenService.validate(tampered);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo(RejectionReason.SIGNATURE_INVALID);
    }

    @Test
    @DisplayName("过期令牌 -> TOKEN_EXPIRED，且与篡改/撤销原因不同")
    void expiredToken() {
        GuardrailProperties expiredProps = new GuardrailProperties();
        expiredProps.getToken().setTtlSeconds(0);
        HmacTokenService expiredService = new HmacTokenService(expiredProps, new UserDirectory());

        TokenService.IssuedToken issued = expiredService.issue(alice);
        AccessDecision decision = expiredService.validate(issued.token());

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo(RejectionReason.TOKEN_EXPIRED);
        assertThat(decision.message()).contains("过期");
    }

    @Test
    @DisplayName("单令牌注销后立即失效 -> TOKEN_REVOKED")
    void revokeCurrentTokenTakesEffectImmediately() {
        TokenService.IssuedToken issued = tokenService.issue(alice);
        assertThat(tokenService.validate(issued.token()).allowed()).isTrue();

        tokenService.revoke(issued.token());

        AccessDecision decision = tokenService.validate(issued.token());
        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo(RejectionReason.TOKEN_REVOKED);
    }

    @Test
    @DisplayName("批量注销使旧令牌全部失效，之后签发的新令牌仍可用")
    void revokeAllOnlyInvalidatesExistingTokens() {
        TokenService.IssuedToken old1 = tokenService.issue(alice);
        TokenService.IssuedToken old2 = tokenService.issue(alice);

        tokenService.revokeAll("alice");

        assertThat(tokenService.validate(old1.token()).reason()).isEqualTo(RejectionReason.TOKEN_REVOKED);
        assertThat(tokenService.validate(old2.token()).reason()).isEqualTo(RejectionReason.TOKEN_REVOKED);

        TokenService.IssuedToken reissued = tokenService.issue(alice);
        assertThat(tokenService.validate(reissued.token()).allowed()).isTrue();
    }

    @Test
    @DisplayName("不同密钥签发的令牌互相无法通过校验 -> SIGNATURE_INVALID")
    void differentSecretRejectsToken() {
        GuardrailProperties other = new GuardrailProperties();
        other.getToken().setHmacKey("a-completely-different-secret");
        HmacTokenService otherService = new HmacTokenService(other, new UserDirectory());

        TokenService.IssuedToken issued = otherService.issue(alice);

        assertThat(tokenService.validate(issued.token()).reason())
                .isEqualTo(RejectionReason.SIGNATURE_INVALID);
    }
}
