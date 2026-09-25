package com.github.highcumontoa.springauthzguardrailsjava.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.springauthzguardrailsjava.domain.UserAccount;
import com.github.highcumontoa.springauthzguardrailsjava.web.ApiError;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 统一安全守卫过滤器，判定顺序固定：
 *
 * <ol>
 *   <li>认证：令牌缺失/篡改/过期/撤销 -> 401，原因互不相同；</li>
 *   <li>访问限流：按主体统计滑动窗口内的成功认证请求，超限 -> 429；</li>
 *   <li>授权：按“路径+方法”所需权限判定，无权 -> 403。</li>
 * </ol>
 *
 * 未认证（401）与已认证但无权（403）结论不同；限流先于授权判定，
 * 保证三类拒绝原因不会相互掩盖。每次拒绝都打印判定依据日志。
 */
public class GuardrailFilter extends OncePerRequestFilter {

    public static final String CURRENT_USER_ATTRIBUTE =
            GuardrailFilter.class.getName() + ".CURRENT_USER";
    public static final String CURRENT_TOKEN_ATTRIBUTE =
            GuardrailFilter.class.getName() + ".CURRENT_TOKEN";

    private static final Logger log = LoggerFactory.getLogger(GuardrailFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final TokenService tokenService;
    private final SlidingWindowRateLimiter accessRateLimiter;
    private final AuthorizationRules authorizationRules;
    private final ObjectMapper objectMapper;

    public GuardrailFilter(TokenService tokenService,
                           SlidingWindowRateLimiter accessRateLimiter,
                           AuthorizationRules authorizationRules,
                           ObjectMapper objectMapper) {
        this.tokenService = tokenService;
        this.accessRateLimiter = accessRateLimiter;
        this.authorizationRules = authorizationRules;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // 只有登录接口是公开的；注销同样需要携带有效令牌
        String path = request.getRequestURI();
        return "/api/auth/login".equals(path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        String method = request.getMethod();

        // 1) 认证
        String rawToken = extractToken(request);
        AccessDecision authDecision = tokenService.validate(rawToken);
        if (!authDecision.allowed()) {
            // 未认证场景没有主体，限流无法按主体归因，故认证先于限流
            reject(response, authDecision.reason(), authDecision.message(),
                    401, "anonymous", method, path);
            return;
        }

        UserAccount user = authDecision.user();

        // 2) 访问限流（按主体统计，只统计通过认证的请求）
        if (!accessRateLimiter.tryAcquire("access:" + user.getUsername())) {
            reject(response, RejectionReason.ACCESS_RATE_LIMITED,
                    "访问过于频繁，已超过滑动窗口阈值，请稍后再试",
                    429, user.getUsername(), method, path);
            return;
        }

        // 3) 授权
        if (!authorizationRules.isAllowed(user, method, path)) {
            // 无权请求在此直接返回，不会进入控制器，因此不会产生任何副作用
            String required = authorizationRules.requiredPermission(method, path);
            String detail = "无权访问 " + method + " " + path
                    + (required != null ? "，所需权限=" + required : "，该路径未声明授权规则（默认拒绝）");
            reject(response, RejectionReason.ACCESS_DENIED, detail,
                    403, user.getUsername(), method, path);
            return;
        }

        request.setAttribute(CURRENT_USER_ATTRIBUTE, user);
        request.setAttribute(CURRENT_TOKEN_ATTRIBUTE, rawToken);
        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return header.substring(BEARER_PREFIX.length()).trim();
    }

    private void reject(HttpServletResponse response,
                        RejectionReason reason,
                        String message,
                        int status,
                        String subject,
                        String method,
                        String path) throws IOException {
        // 单测与运行日志中均打印被拒绝请求的判定依据
        log.warn("请求被拒绝 subject={} {} {} status={} reason={} basis={}",
                subject, method, path, status, reason, message);
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        objectMapper.writeValue(response.getWriter(), new ApiError(reason.name(), message, status));
    }
}
