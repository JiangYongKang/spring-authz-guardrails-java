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
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 续期凭据服务：签发、校验、一次性轮换、主体级撤销。
 *
 * 凭据结构与访问令牌相同：base64url(header).base64url(payload).base64url(HMAC-SHA256签名)，
 * 但使用独立密钥且 payload 含 "kind":"refresh"，因此访问令牌与续期凭据不可互相冒充。
 *
 * 生命周期机制：
 *  - 有效期：payload 的 exp，由 security.refresh-token.ttl-seconds 控制（默认 1209600 秒 = 14 天）；
 *  - 轮换一次性：成功轮换时 jti 原子进入“已使用”集合，旧凭据立即作废，并发重放仅一次成功；
 *  - 主体级撤销（注销）：主体持有单调递增的注销代号 gen，凡 gen 不匹配当前代号的凭据一律失效；
 *    重新登录不回退代号，新凭据携带新代号，已撤销的旧凭据不会因重新登录而复活；
 *  - 校验顺序：结构/签名（篡改） -> 过期 -> 代号（撤销） -> 一次性（已使用），各原因可区分。
 */
@Service
public class RefreshTokenService {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private final byte[] secret;
    private final long ttlSeconds;
    private final Clock clock;

    /** 主体 -> 会话状态（当前代号 + 已轮换凭据）。 */
    private final Map<String, State> states = new ConcurrentHashMap<>();

    @org.springframework.beans.factory.annotation.Autowired
    public RefreshTokenService(
            @Value("${security.refresh-token.ttl-seconds:1209600}") long ttlSeconds, Clock clock) {
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

    /** 主体当前注销代号（从未注销或未登录过为 0）。 */
    public long currentGeneration(String subject) {
        State s = states.get(subject);
        return s == null ? 0L : s.generation;
    }

    /** 签发新的续期凭据，携带指定的注销代号。 */
    public String issueToken(String subject, long generation) {
        long now = clock.instant().getEpochSecond();
        String header = "{\"alg\":\"HS256\",\"typ\":\"RFT\"}";
        String payload = "{"
                + "\"sub\":\"" + escape(subject) + "\","
                + "\"kind\":\"refresh\","
                + "\"iat\":" + now + ","
                + "\"exp\":" + (now + ttlSeconds) + ","
                + "\"gen\":" + generation + ","
                + "\"jti\":\"" + UUID.randomUUID() + "\""
                + "}";
        String unsigned = B64.encodeToString(header.getBytes(StandardCharsets.UTF_8))
                + "." + B64.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        return unsigned + "." + B64.encodeToString(sign(unsigned));
    }

    /**
     * 轮换：原子地消耗旧凭据。同一凭据并发提交至多一次成功，其余得到 REFRESH_USED，
     * 且失败不会产生任何新凭据（新凭据由调用方在成功后签发）。
     * 代号以服务内部当前值为准，凭据内代号必须与之相等，否则按 REFRESH_REVOKED 拒绝。
     */
    public RefreshResult rotate(String token) {
        Claims claims;
        try {
            claims = parseAndVerify(token);
        } catch (TokenRejected rejected) {
            return RefreshResult.fail(rejected.reason);
        }
        long now = clock.instant().getEpochSecond();
        if (now >= claims.exp) {
            return RefreshResult.fail(RefreshFailureReason.REFRESH_EXPIRED);
        }
        final long claimExp = claims.exp;
        State locked = states.compute(claims.subject, (k, old) -> {
            State s = old == null ? new State(0L) : old;
            s.pruneExpired(now);
            return s;
        });
        synchronized (locked) {
            if (claims.generation != locked.generation) {
                return RefreshResult.fail(RefreshFailureReason.REFRESH_REVOKED);
            }
            if (locked.usedJti.putIfAbsent(claims.jti, claimExp) != null) {
                return RefreshResult.fail(RefreshFailureReason.REFRESH_USED);
            }
            return RefreshResult.ok(claims.subject, locked.generation);
        }
    }

    /** 仅校验不消耗（测试/探查用），顺序与轮换一致。 */
    public RefreshResult inspect(String token) {
        Claims claims;
        try {
            claims = parseAndVerify(token);
        } catch (TokenRejected rejected) {
            return RefreshResult.fail(rejected.reason);
        }
        long now = clock.instant().getEpochSecond();
        if (now >= claims.exp) {
            return RefreshResult.fail(RefreshFailureReason.REFRESH_EXPIRED);
        }
        State s = states.get(claims.subject);
        long current = s == null ? 0L : s.generation;
        if (claims.generation != current) {
            return RefreshResult.fail(RefreshFailureReason.REFRESH_REVOKED);
        }
        if (s != null && s.usedJti.containsKey(claims.jti)) {
            return RefreshResult.fail(RefreshFailureReason.REFRESH_USED);
        }
        return RefreshResult.ok(claims.subject, current);
    }

    /** 注销：主体代号前进一代。此前签发的续期凭据立即全部失效，代号单调递增不回退。 */
    public void revokeAllForSubject(String subject) {
        states.compute(subject, (k, old) -> {
            State s = old == null ? new State(0L) : old;
            s.generation++;
            return s;
        });
    }

    // ---------- 内部 ----------

    private Claims parseAndVerify(String token) throws TokenRejected {
        if (token == null || token.isBlank()) {
            throw new TokenRejected(RefreshFailureReason.REFRESH_MISSING);
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new TokenRejected(RefreshFailureReason.REFRESH_TAMPERED);
        }
        String unsigned = parts[0] + "." + parts[1];
        byte[] actualSig;
        try {
            actualSig = B64D.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new TokenRejected(RefreshFailureReason.REFRESH_TAMPERED);
        }
        if (!MessageDigest.isEqual(sign(unsigned), actualSig)) {
            throw new TokenRejected(RefreshFailureReason.REFRESH_TAMPERED);
        }
        Map<String, String> raw;
        try {
            raw = parsePayload(new String(B64D.decode(parts[1]), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new TokenRejected(RefreshFailureReason.REFRESH_TAMPERED);
        }
        String subject = raw.get("sub");
        String jti = raw.get("jti");
        String kind = raw.get("kind");
        long exp = parseLong(raw.get("exp"), -1);
        long gen = parseLong(raw.get("gen"), Long.MIN_VALUE);
        if (subject == null || jti == null || exp < 0 || gen == Long.MIN_VALUE
                || !"refresh".equals(kind)) {
            // 缺少必要声明，或拿访问令牌（无 kind=refresh）冒充续期凭据
            throw new TokenRejected(RefreshFailureReason.REFRESH_TAMPERED);
        }
        return new Claims(subject, jti, exp, gen);
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

    private record Claims(String subject, String jti, long exp, long generation) {
    }

    private static final class TokenRejected extends Exception {
        private final RefreshFailureReason reason;

        TokenRejected(RefreshFailureReason reason) {
            super(reason.name());
            this.reason = reason;
        }
    }

    /** 主体会话状态：当前注销代号 + 已轮换（消耗）的凭据编号集合。 */
    private static final class State {
        private long generation;
        /** jti -> 过期秒，过期后惰性清理，避免无限增长。 */
        private final Map<String, Long> usedJti = new ConcurrentHashMap<>();

        State(long generation) {
            this.generation = generation;
        }

        void pruneExpired(long nowSeconds) {
            usedJti.entrySet().removeIf(e -> e.getValue() <= nowSeconds);
        }
    }
}
