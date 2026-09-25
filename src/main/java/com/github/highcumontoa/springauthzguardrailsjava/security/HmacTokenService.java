package com.github.highcumontoa.springauthzguardrailsjava.security;

import com.github.highcumontoa.springauthzguardrailsjava.config.GuardrailProperties;
import com.github.highcumontoa.springauthzguardrailsjava.domain.UserAccount;
import com.github.highcumontoa.springauthzguardrailsjava.store.UserDirectory;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 自包含的本地访问令牌服务，不依赖外部身份提供商。
 *
 * <p>令牌格式为 {@code payload.signature}：
 * <ul>
 *   <li>payload = base64url(username|issuedAt|expiresAt|jti)</li>
 *   <li>signature = hex(HmacSHA256(payload, 本地密钥))</li>
 * </ul>
 *
 * <p>校验顺序固定且原因可区分：
 * 格式非法 -> 签名不匹配 -> 已过期 -> 已撤销 -> 主体不存在。
 */
@Service
public class HmacTokenService implements TokenService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String DELIMITER = "|";

    private final GuardrailProperties properties;
    private final UserDirectory userDirectory;

    /** 已撤销的单个令牌 jti 集合。 */
    private final Set<String> revokedTokens = ConcurrentHashMap.newKeySet();
    /** 每个主体被“全部撤销”之后仍保留的活动令牌映射，用于精确注销语义。 */
    private final Map<String, Set<String>> activeTokensByUser = new ConcurrentHashMap<>();
    /** 执行“撤销该主体全部令牌”时的时间点：早于该时间签发的令牌一律视为已撤销。 */
    private final Map<String, Long> revokeAllBefore = new ConcurrentHashMap<>();

    public HmacTokenService(GuardrailProperties properties, UserDirectory userDirectory) {
        this.properties = properties;
        this.userDirectory = userDirectory;
    }

    @Override
    public IssuedToken issue(UserAccount user) {
        long now = System.currentTimeMillis() / 1000L;
        long expiresAt = now + properties.getToken().getTtlSeconds();
        String jti = UUID.randomUUID().toString().replace("-", "");
        String payloadBody = String.join(DELIMITER, user.getUsername(),
                Long.toString(now), Long.toString(expiresAt), jti);
        String payload = encode(payloadBody);
        String token = payload + "." + sign(payload);

        activeTokensByUser
                .computeIfAbsent(user.getUsername(), k -> ConcurrentHashMap.newKeySet())
                .add(jti);
        return new IssuedToken(token, expiresAt);
    }

    @Override
    public AccessDecision validate(String token) {
        if (token == null || token.isBlank()) {
            return AccessDecision.reject(RejectionReason.MISSING_TOKEN, "缺少访问令牌");
        }
        int dot = token.lastIndexOf('.');
        if (dot <= 0 || dot == token.length() - 1) {
            return AccessDecision.reject(RejectionReason.MALFORMED_TOKEN, "令牌格式非法");
        }
        String payload = token.substring(0, dot);
        String signature = token.substring(dot + 1);

        String body;
        try {
            if (!constantTimeEquals(signature, sign(payload))) {
                return AccessDecision.reject(RejectionReason.SIGNATURE_INVALID, "令牌签名校验失败，令牌可能已被篡改");
            }
            body = decode(payload);
        } catch (IllegalArgumentException e) {
            return AccessDecision.reject(RejectionReason.MALFORMED_TOKEN, "令牌内容无法解析");
        }

        String[] parts = body.split("\\" + DELIMITER, -1);
        if (parts.length != 4) {
            return AccessDecision.reject(RejectionReason.MALFORMED_TOKEN, "令牌字段数量不正确");
        }
        String username = parts[0];
        long issuedAt;
        long expiresAt;
        String jti = parts[3];
        try {
            issuedAt = Long.parseLong(parts[1]);
            expiresAt = Long.parseLong(parts[2]);
        } catch (NumberFormatException e) {
            return AccessDecision.reject(RejectionReason.MALFORMED_TOKEN, "令牌时间戳字段非法");
        }

        long now = System.currentTimeMillis() / 1000L;
        if (now >= expiresAt) {
            return AccessDecision.reject(RejectionReason.TOKEN_EXPIRED,
                    "令牌已于 " + expiresAt + " 过期（当前 " + now + "）");
        }

        if (revokedTokens.contains(jti)) {
            return AccessDecision.reject(RejectionReason.TOKEN_REVOKED, "令牌已被主动注销");
        }
        Long revokeBefore = revokeAllBefore.get(username);
        if (revokeBefore != null && issuedAt < revokeBefore) {
            return AccessDecision.reject(RejectionReason.TOKEN_REVOKED, "该主体的令牌已在批量注销中失效");
        }

        Optional<UserAccount> account = userDirectory.findByUsername(username);
        if (account.isEmpty()) {
            return AccessDecision.reject(RejectionReason.MALFORMED_TOKEN, "令牌对应的主体不存在");
        }
        return AccessDecision.permit(account.get());
    }

    @Override
    public void revoke(String token) {
        if (token == null) {
            return;
        }
        int dot = token.lastIndexOf('.');
        if (dot <= 0) {
            return;
        }
        try {
            String body = decode(token.substring(0, dot));
            String[] parts = body.split("\\" + DELIMITER, -1);
            if (parts.length == 4) {
                revokedTokens.add(parts[3]);
            }
        } catch (IllegalArgumentException ignored) {
            // 注销的令牌本身可能已损坏，忽略即可，损坏令牌本来也无法通过校验
        }
    }

    @Override
    public void revokeAll(String username) {
        long now = System.currentTimeMillis() / 1000L;
        revokeAllBefore.put(username, now);
        Set<String> active = activeTokensByUser.get(username);
        if (active != null) {
            revokedTokens.addAll(active);
            active.clear();
        }
    }

    private String sign(String payload) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            byte[] keyBytes = digestKey(properties.getToken().getHmacKey());
            mac.init(new SecretKeySpec(keyBytes, HMAC_ALGORITHM));
            byte[] raw = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(raw);
        } catch (Exception e) {
            throw new IllegalStateException("无法计算令牌签名", e);
        }
    }

    private static byte[] digestKey(String key) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(key.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("无法派生签名密钥", e);
        }
    }

    private static String encode(String body) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(body.getBytes(StandardCharsets.UTF_8));
    }

    private static String decode(String payload) {
        byte[] raw = Base64.getUrlDecoder().decode(payload);
        return new String(raw, StandardCharsets.UTF_8);
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }
}
