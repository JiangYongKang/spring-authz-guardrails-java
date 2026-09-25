package com.github.highcumontoa.springauthzguardrailsjava.web;

import java.util.Set;

/**
 * 已认证主体的请求上下文。
 */
public record AuthContext(String subject, Set<String> permissions) {
}
