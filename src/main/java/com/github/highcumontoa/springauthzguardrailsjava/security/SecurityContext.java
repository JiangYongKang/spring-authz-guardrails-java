package com.github.highcumontoa.springauthzguardrailsjava.security;

import com.github.highcumontoa.springauthzguardrailsjava.domain.UserAccount;
import jakarta.servlet.http.HttpServletRequest;

/**
 * 从经过 {@link GuardrailFilter} 校验后的请求中取出当前主体。
 */
public final class SecurityContext {

    private SecurityContext() {
    }

    public static UserAccount currentUser(HttpServletRequest request) {
        Object user = request.getAttribute(GuardrailFilter.CURRENT_USER_ATTRIBUTE);
        if (user instanceof UserAccount account) {
            return account;
        }
        throw new GuardrailRejectionException(RejectionReason.ACCESS_DENIED,
                "无法从安全上下文中解析当前主体", 403);
    }

    public static String currentToken(HttpServletRequest request) {
        Object token = request.getAttribute(GuardrailFilter.CURRENT_TOKEN_ATTRIBUTE);
        return token == null ? null : token.toString();
    }
}
