package com.github.highcumontoa.springauthzguardrailsjava.auth;

import com.github.highcumontoa.springauthzguardrailsjava.authz.Role;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 本地凭据存储（内存实现，不依赖外部身份服务）。
 * 口令以 SHA-256(盐 + 口令) 的十六进制形式保存，绝不保存明文。
 */
@Component
public class CredentialStore {

    private final Map<String, UserAccount> accounts = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public CredentialStore() {
        // 预置本地演示账号，覆盖三种角色
        register("alice", "alice-pass", Role.USER);
        register("bob", "bob-pass", Role.ADMIN);
        register("carol", "carol-pass", Role.GUEST);
    }

    public void register(String username, String rawPassword, Role role) {
        byte[] saltBytes = new byte[16];
        random.nextBytes(saltBytes);
        String salt = HexFormat.of().formatHex(saltBytes);
        accounts.put(username, new UserAccount(username, hash(salt, rawPassword), salt, role.permissions()));
    }

    public Optional<UserAccount> findByUsername(String username) {
        return Optional.ofNullable(accounts.get(username));
    }

    public boolean verifyPassword(UserAccount account, String rawPassword) {
        String candidate = hash(account.salt(), rawPassword);
        // 常量时间比较，避免时序侧信道
        return MessageDigest.isEqual(candidate.getBytes(StandardCharsets.UTF_8),
                account.passwordHash().getBytes(StandardCharsets.UTF_8));
    }

    static String hash(String salt, String rawPassword) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] out = digest.digest((salt + ":" + rawPassword).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(out);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
