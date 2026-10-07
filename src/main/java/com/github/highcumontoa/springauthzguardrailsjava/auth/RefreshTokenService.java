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
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 续期凭据服务：签发、校验、轮换、撤销。
 *
 * 凭据结构与访问令牌相同（header.payload.signature 三段 HMAC-SHA256），但：
 *  - 使用独立签名密钥，且 payload 携带 typ=refresh 声明，与访问令牌不可混用；
 *  - 有效期由 security.refresh.ttl-seconds 独立控制（默认 7 天）。
 *
 * 轮换（rotation）：每次续期成功都换发新凭据，旧凭据的 jti 进入已消费集合并当场作废；
 * 同一旧凭据并发提交时， consumedJti.add 的原子性保证最多只有一次成功。
 *
 * 注销：按主体维护单调递增的纪元号（epoch），凭据携带签发时的纪元；
 * 注销即递增纪元，此前签发的凭据纪元不再匹配、立即失效；
 * 重新登录签发的凭据使用新纪元，立即可用；已撤销凭据不会因重新登录而复效。
 */
@Service
public class RefreshTokenService {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();
    private static final String TYP = "refresh";

    private final byte[] secret;
    private final long ttlSeconds;
    private final Clock clock;

    /** 已消费（已轮换作废）的凭据编号 */
    private final Set<String> consumedJti = ConcurrentHashMap.newKeySet();
    /** 主体 -> 当前纪元号，注销即递增 */
    private final Map<String, AtomicLong> subjectEpoch = new ConcurrentHashMap<>();

    @org.springframework.beans.factory.annotation.Autowired
    public RefreshTokenService(@Value("${security.refresh.ttl-seconds:604800}") long ttlSeconds,
                               Clock clock) {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        this.secret = key;
        this.ttlSeconds = ttlSeconds;
        this.clock = clock;
    }

    /** 测试专用：可注入固定密钥与时钟。 */
    public RefreshTokenService(byte[] secret, long ttlSeconds, Clock clock) {
        this.secret = secret.clone();
        this.ttlSeconds = ttlSeconds;
        this.clock = clock;
    }

    /** 签发续期凭据，权限快照自登录时刻，续期换发的访问令牌与其保持一致。 */
    public String issueRefreshToken(String subject, Set<String> permissions) {
        long now = clock.instant().getEpochSecond();
        long epoch = currentEpoch(subject);
        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payload = "{"
                + "\"sub\":\"" + escape(subject) + "\","
                + "\"perms\":\"" + escape(String.join(",", permissions)) + "\","
                + "\"iat\":" + now + ","
                + "\"exp\":" + (now + ttlSeconds) + ","
                + "\"jti\":\"" + UUID.randomUUID() + "\","
                + "\"typ\":\"" + TYP + "\","
                + "\"se\":" + epoch
                + "}";
        String unsigned = B64.encodeToString(header.getBytes(StandardCharsets.UTF_8))
                + "." + B64.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        return unsigned + "." + B64.encodeToString(sign(unsigned));
    }

    /**
     * 用旧续期凭据轮换新凭据。校验顺序：结构/签名（篡改） -> 类型 -> 撤销/已消费 -> 过期。
     * 校验通过后原子地将旧 jti 标记为已消费：并发重复提交最多只有一次成功，
     * 其余以 REFRESH_TOKEN_REVOKED 拒绝，且不会因此多出可用凭据。
     */
    public RefreshResult rotate(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return RefreshResult.fail(AuthFailureReason.REFRESH_TOKEN_MISSING);
        }
        String[] parts = refreshToken.split("\\.");
        if (parts.length != 3) {
            return RefreshResult.fail(AuthFailureReason.REFRESH_TOKEN_TAMPERED);
        }
        String unsigned = parts[0] + "." + parts[1];
        byte[] actualSig;
        try {
            actualSig = B64D.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            return RefreshResult.fail(AuthFailureReason.REFRESH_TOKEN_TAMPERED);
        }
        if (!MessageDigest.isEqual(sign(unsigned), actualSig)) {
            return RefreshResult.fail(AuthFailureReason.REFRESH_TOKEN_TAMPERED);
        }
        Map<String, String> claims;
        try {
            claims = parsePayload(new String(B64D.decode(parts[1]), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            return RefreshResult.fail(AuthFailureReason.REFRESH_TOKEN_TAMPERED);
        }
        String jti = claims.get("jti");
        String subject = claims.get("sub");
        if (jti == null || subject == null || !TYP.equals(claims.get("typ"))) {
            // 访问令牌或其它类型令牌不能当作续期凭据使用
            return RefreshResult.fail(AuthFailureReason.REFRESH_TOKEN_TAMPERED);
        }
        // 撤销判定优先于过期判定
        if (consumedJti.contains(jti)) {
            return RefreshResult.fail(AuthFailureReason.REFRESH_TOKEN_REVOKED);
        }
        long se = parseLong(claims.get("se"), -1);
        if (se < 0 || se != currentEpoch(subject)) {
            return RefreshResult.fail(AuthFailureReason.REFRESH_TOKEN_REVOKED);
        }
        long exp = parseLong(claims.get("exp"), -1);
        if (exp < 0 || clock.instant().getEpochSecond() >= exp) {
            return RefreshResult.fail(AuthFailureReason.REFRESH_TOKEN_EXPIRED);
        }
        // 一次性消费：原子占位，并发下仅一个线程能成功
        if (!consumedJti.add(jti)) {
            return RefreshResult.fail(AuthFailureReason.REFRESH_TOKEN_REVOKED);
        }
        Set<String> perms = claims.get("perms") == null || claims.get("perms").isEmpty()
                ? Set.of()
                : Set.of(claims.get("perms").split(","));
        return RefreshResult.ok(subject, perms, issueRefreshToken(subject, perms));
    }

    /** 注销：递增主体纪元，此前签发的全部续期凭据立即失效且不可复效。 */
    public void revokeAllForSubject(String subject) {
        subjectEpoch.computeIfAbsent(subject, k -> new AtomicLong()).incrementAndGet();
    }

    private long currentEpoch(String subject) {
        AtomicLong epoch = subjectEpoch.get(subject);
        return epoch == null ? 0 : epoch.get();
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
}
