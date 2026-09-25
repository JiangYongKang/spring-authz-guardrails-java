package com.github.highcumontoa.springauthzguardrailsjava.auth;

import java.util.Set;

/**
 * 本地账号：用户名、加盐哈希后的口令、权限集合。
 */
public record UserAccount(String username, String passwordHash, String salt, Set<String> permissions) {
}
