package com.github.highcumontoa.springauthzguardrailsjava.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 访问令牌服务：签发、校验、主动失效。
 *
 * 令牌结构：base64url(headerJson).base64url(payloadJson).base64url(hmacSha256)。
 * payload 含 sub(主体)、perms(权限)、iat(签发秒)、exp(过期秒)、jti(唯一编号)。
 *
 * 失效机制：
 *  - 单令牌撤销：jti 进入撤销集合；
 *  - 主体级撤销（注销）：主体持有单调递增的“注销代号”，令牌 payload 的 rvv 声明记录签发时代号，
 *    代号不匹配当前值即失效。代号只增不减，因此注销后立刻重新登录也不会把旧令牌“复活”，
 *    且同一秒内完成注销+重新登录不会误伤新令牌（不依赖秒级时间戳）。
 */
@Service
public class TokenService {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private final byte[] secret;
    private final long ttlSeconds;
    private final Clock clock;

    /** 已撤销的令牌编号 */
    private final Set<String> revokedJti = ConcurrentHashMap.newKeySet();
    /** 主体 -> 当前注销代号，rvv 不等于该值的令牌全部失效；代号单调递增 */
    private final Map<String, Long> subjectGeneration = new ConcurrentHashMap<>();

    @org.springframework.beans.factory.annotation.Autowired
    public TokenService(@Value("${security.token.ttl-seconds:300}") long ttlSeconds, Clock clock) {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        this.secret = key;
        this.ttlSeconds = ttlSeconds;
        this.clock = clock;
    }

    /** 测试专用：可注入固定密钥与时钟。 */
    public TokenService(byte[] secret, long ttlSeconds, Clock clock) {
        this.secret = secret.clone();
        this.ttlSeconds = ttlSeconds;
        this.clock = clock;
    }

    /** 主体当前注销代号（从未注销或未登录过为 0）。 */
    public long currentGeneration(String subject) {
        return subjectGeneration.getOrDefault(subject, 0L);
    }

    public String issueToken(String subject, Set<String> permissions) {
        return issueToken(subject, permissions, currentGeneration(subject));
    }

    /** 签发携带指定注销代号的访问令牌（登录/续期换发时使用）。 */
    public String issueToken(String subject, Set<String> permissions, long generation) {
        long now = clock.instant().getEpochSecond();
        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payload = "{"
                + "\"sub\":\"" + escape(subject) + "\","
                + "\"perms\":\"" + escape(String.join(",", permissions)) + "\","
                + "\"iat\":" + now + ","
                + "\"exp\":" + (now + ttlSeconds) + ","
                + "\"rvv\":" + generation + ","
                + "\"jti\":\"" + UUID.randomUUID() + "\""
                + "}";
        String unsigned = B64.encodeToString(header.getBytes(StandardCharsets.UTF_8))
                + "." + B64.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        return unsigned + "." + B64.encodeToString(sign(unsigned));
    }

    /**
     * 校验令牌。校验顺序：结构/签名（篡改） -> 撤销 -> 过期，各原因可区分。
     */
    public AuthResult validate(String token) {
        if (token == null || token.isBlank()) {
            return AuthResult.fail(AuthFailureReason.TOKEN_MISSING);
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return AuthResult.fail(AuthFailureReason.TOKEN_TAMPERED);
        }
        String unsigned = parts[0] + "." + parts[1];
        byte[] expectedSig = sign(unsigned);
        byte[] actualSig;
        try {
            actualSig = B64D.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            return AuthResult.fail(AuthFailureReason.TOKEN_TAMPERED);
        }
        if (!MessageDigest.isEqual(expectedSig, actualSig)) {
            return AuthResult.fail(AuthFailureReason.TOKEN_TAMPERED);
        }
        Map<String, String> claims;
        try {
            claims = parsePayload(new String(B64D.decode(parts[1]), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            return AuthResult.fail(AuthFailureReason.TOKEN_TAMPERED);
        }
        String jti = claims.get("jti");
        String subject = claims.get("sub");
        if (jti == null || subject == null) {
            return AuthResult.fail(AuthFailureReason.TOKEN_TAMPERED);
        }
        // 撤销判定优先于过期判定：被撤销的令牌无论是否过期都以 REVOKED 拒绝
        if (revokedJti.contains(jti)) {
            return AuthResult.fail(AuthFailureReason.TOKEN_REVOKED);
        }
        // 无 rvv 声明的旧令牌视为第 0 代；与当前代号不一致即已被注销作废
        long tokenGeneration = parseLong(claims.get("rvv"), 0);
        if (tokenGeneration != subjectGeneration.getOrDefault(subject, 0L)) {
            return AuthResult.fail(AuthFailureReason.TOKEN_REVOKED);
        }
        long exp = parseLong(claims.get("exp"), -1);
        if (exp < 0 || clock.instant().getEpochSecond() >= exp) {
            return AuthResult.fail(AuthFailureReason.TOKEN_EXPIRED);
        }
        Set<String> perms = claims.get("perms") == null || claims.get("perms").isEmpty()
                ? Set.of()
                : Set.of(claims.get("perms").split(","));
        return AuthResult.ok(subject, perms);
    }

    /** 撤销单个令牌（按 jti）。 */
    public void revoke(String token) {
        String[] parts = token == null ? new String[0] : token.split("\\.");
        if (parts.length == 3) {
            try {
                Map<String, String> claims =
                        parsePayload(new String(B64D.decode(parts[1]), StandardCharsets.UTF_8));
                String jti = claims.get("jti");
                if (jti != null) {
                    revokedJti.add(jti);
                }
            } catch (IllegalArgumentException ignored) {
                // 非法令牌无需撤销
            }
        }
    }

    /** 注销：注销代号前进一步，使该主体此前签发的所有令牌立即失效；代号不回退。 */
    public void revokeAllForSubject(String subject) {
        subjectGeneration.merge(subject, 1L, Math::addExact);
    }

    private byte[] sign(String unsigned) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(unsigned.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    /** 极简 JSON 解析：仅支持本服务签发的扁平 {"k":"v"/"k":number} 结构。 */
    private static Map<String, String> parsePayload(String json) {
        Map<String, String> map = new LinkedHashMap<>();
        String body = json.trim();
        if (!body.startsWith("{") || !body.endsWith("}")) {
            throw new IllegalArgumentException("bad payload");
        }
        body = body.substring(1, body.length() - 1).trim();
        if (body.isEmpty()) {
            return map;
        }
        for (String pair : splitTopLevel(body)) {
            int colon = pair.indexOf(':');
            if (colon <= 0) {
                throw new IllegalArgumentException("bad pair");
            }
            String key = unquote(pair.substring(0, colon).trim());
            String value = pair.substring(colon + 1).trim();
            map.put(key, value.startsWith("\"") ? unquote(value) : value);
        }
        return map;
    }

    private static String[] splitTopLevel(String body) {
        java.util.List<String> parts = new java.util.ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inString = false;
        for (char c : body.toCharArray()) {
            if (c == '"') {
                inString = !inString;
            }
            if (c == ',' && !inString) {
                parts.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        parts.add(cur.toString());
        return parts.toArray(new String[0]);
    }

    private static String unquote(String s) {
        if (s.length() < 2 || !s.startsWith("\"") || !s.endsWith("\"")) {
            throw new IllegalArgumentException("bad string");
        }
        return s.substring(1, s.length() - 1);
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static long parseLong(String s, long fallback) {
        try {
            return s == null ? fallback : Long.parseLong(s);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    /** 测试辅助：当前时间。 */
    Instant now() {
        return clock.instant();
    }
}
