package com.github.highcumontoa.springauthzguardrailsjava.security;

import com.github.highcumontoa.springauthzguardrailsjava.domain.UserAccount;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.regex.Pattern;

/**
 * 基于“路径 + HTTP 方法 -> 所需权限”的本地授权规则。
 *
 * <p>模型说明：
 * <ul>
 *   <li>角色（ROLE）是粗粒度分组，权限（PERMISSION，形如 {@code 资源:动作}）是细粒度判定依据；</li>
 *   <li>直接按权限判定，ADMIN 角色隐含全部权限；</li>
 *   <li>部分路由（如注销）只需“已认证”，不要求特定权限；</li>
 *   <li>规则按声明顺序匹配，{@code *} 匹配单段路径，未命中任何规则默认拒绝（fail-closed）。</li>
 * </ul>
 */
@Component
public class AuthorizationRules {

    private static final String ROLE_ADMIN = "ADMIN";
    private static final String AUTHENTICATED_ONLY = "*";

    private final List<Rule> rules = List.of(
            Rule.authenticated("POST", "/api/auth/logout"),
            Rule.protected_("GET", "/api/profile/me", "profile:read"),
            Rule.protected_("GET", "/api/users", "user:list"),
            Rule.protected_("DELETE", "/api/users/*", "user:delete"),
            Rule.protected_("GET", "/api/admin/ping", "admin:read")
    );

    public boolean isAllowed(UserAccount user, String method, String path) {
        if (user == null) {
            return false;
        }
        Rule rule = match(method, path);
        if (rule == null) {
            return false;
        }
        if (AUTHENTICATED_ONLY.equals(rule.requiredPermission())) {
            return true;
        }
        if (user.getRoles().contains(ROLE_ADMIN)) {
            return true;
        }
        return user.getPermissions().contains(rule.requiredPermission());
    }

    /**
     * 返回某条路由要求的权限：{@code "*"} 表示仅需认证；{@code null} 表示路由未声明规则。
     * 用于生成可解释的拒绝日志。
     */
    public String requiredPermission(String method, String path) {
        Rule rule = match(method, path);
        return rule == null ? null : rule.requiredPermission();
    }

    private Rule match(String method, String path) {
        for (Rule rule : rules) {
            if (rule.method().equals(method) && rule.pathPattern().matcher(path).matches()) {
                return rule;
            }
        }
        return null;
    }

    private record Rule(String method, Pattern pathPattern, String requiredPermission) {

        private static Rule protected_(String method, String pathPattern, String permission) {
            return new Rule(method, compile(pathPattern), permission);
        }

        private static Rule authenticated(String method, String pathPattern) {
            return new Rule(method, compile(pathPattern), AUTHENTICATED_ONLY);
        }

        private static Pattern compile(String pathPattern) {
            String regex = Pattern.quote(pathPattern).replace("*", "\\E[^/]+\\Q");
            return Pattern.compile(regex);
        }
    }
}
