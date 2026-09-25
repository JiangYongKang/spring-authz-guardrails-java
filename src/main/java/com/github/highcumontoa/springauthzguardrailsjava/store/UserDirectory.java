package com.github.highcumontoa.springauthzguardrailsjava.store;

import com.github.highcumontoa.springauthzguardrailsjava.domain.UserAccount;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 纯内存的本地用户目录，不依赖任何外部身份服务。
 * 密码仅为本地演示用途的明文比对，真实系统应使用加盐哈希。
 */
@Component
public class UserDirectory {

    private final Map<String, UserAccount> users = new ConcurrentHashMap<>();

    public UserDirectory() {
        register(new UserAccount(
                "alice", "password-alice",
                Set.of("USER"),
                Set.of("profile:read")));
        register(new UserAccount(
                "bob", "password-bob",
                Set.of("USER"),
                Set.of("profile:read")));
        register(new UserAccount(
                "admin", "password-admin",
                Set.of("USER", "ADMIN"),
                Set.of("profile:read", "user:list", "user:delete", "admin:read")));
    }

    public final void register(UserAccount account) {
        users.put(account.getUsername(), account);
    }

    public Optional<UserAccount> findByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }
}
