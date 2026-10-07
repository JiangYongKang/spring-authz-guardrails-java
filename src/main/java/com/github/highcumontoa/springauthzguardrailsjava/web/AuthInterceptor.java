package com.github.highcumontoa.springauthzguardrailsjava.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.springauthzguardrailsjava.auth.AuthFailureReason;
import com.github.highcumontoa.springauthzguardrailsjava.auth.AuthResult;
import com.github.highcumontoa.springauthzguardrailsjava.auth.TokenService;
import com.github.highcumontoa.springauthzguardrailsjava.authz.AuthorizationService;
import com.github.highcumontoa.springauthzguardrailsjava.authz.Permission;
import com.github.highcumontoa.springauthzguardrailsjava.ratelimit.RateLimitDecision;
import com.github.highcumontoa.springauthzguardrailsjava.ratelimit.RateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 请求拦截，判定顺序固定为：限流 -> 认证 -> 授权。
 * 任一环节拒绝都返回可区分的结论（HTTP 状态码 + reason 字段），并打印判定依据日志。
 * 被拒绝的请求不会进入控制器，因此不会产生任何副作用。
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    public static final String ATTR_AUTH_CONTEXT = "authContext";

    private static final Logger log = LoggerFactory.getLogger(AuthInterceptor.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final TokenService tokenService;
    private final AuthorizationService authorizationService;
    private final RateLimiter rateLimiter;

    public AuthInterceptor(TokenService tokenService, AuthorizationService authorizationService,
                           @Qualifier("apiRateLimiter") RateLimiter rateLimiter) {
        this.tokenService = tokenService;
        this.authorizationService = authorizationService;
        this.rateLimiter = rateLimiter;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String path = request.getRequestURI();
        String token = extractBearer(request);

        // 1. 限流：优先按令牌主体，无法解析时按来源地址
        String rateKey = resolveRateKey(request, token);
        RateLimitDecision rate = rateLimiter.tryAcquire(rateKey);
        if (!rate.allowed()) {
            deny(response, request, 429, "RATE_LIMITED",
                    "请求超过限流阈值，" + rate.retryAfterMillis() + "ms 后窗口滚动自动恢复");
            return false;
        }

        // 2. 认证
        AuthResult auth = tokenService.validate(token);
        if (!auth.success()) {
            rateLimiter.recordFailure(rateKey);
            deny(response, request, 401, auth.failureReason().name(), describe(auth.failureReason()));
            return false;
        }

        // 3. 授权
        Permission required = requiredPermission(request.getMethod(), path);
        if (required != null && !authorizationService.isAllowed(auth.permissions(), required)) {
            rateLimiter.recordFailure(rateKey);
            deny(response, request, 403, "PERMISSION_DENIED",
                    "主体[" + auth.subject() + "]缺少权限 " + required.name());
            return false;
        }

        request.setAttribute(ATTR_AUTH_CONTEXT, new AuthContext(auth.subject(), auth.permissions()));
        log.info("判定结论: ALLOWED subject={} method={} path={}", auth.subject(), request.getMethod(), path);
        return true;
    }

    /** 路径 -> 所需权限 的静态映射。 */
    static Permission requiredPermission(String method, String path) {
        if (path.startsWith("/api/admin")) {
            return Permission.ADMIN_OPERATE;
        }
        if (path.startsWith("/api/resource")) {
            return switch (method) {
                case "GET" -> Permission.RESOURCE_READ;
                case "POST", "PUT", "DELETE" -> Permission.RESOURCE_WRITE;
                default -> null;
            };
        }
        return null;
    }

    private String resolveRateKey(HttpServletRequest request, String token) {
        if (token != null) {
            AuthResult probe = tokenService.validate(token);
            if (probe.success()) {
                return "sub:" + probe.subject();
            }
        }
        return "ip:" + request.getRemoteAddr();
    }

    private static String extractBearer(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7).trim();
        }
        return null;
    }

    private static String describe(AuthFailureReason reason) {
        return switch (reason) {
            case TOKEN_MISSING -> "未提供访问令牌";
            case TOKEN_TAMPERED -> "令牌格式非法或签名不匹配（疑似被篡改）";
            case TOKEN_EXPIRED -> "令牌已过期";
            case TOKEN_REVOKED -> "令牌已被撤销（注销或主动失效）";
        };
    }

    private void deny(HttpServletResponse response, HttpServletRequest request,
                      int status, String reason, String detail) throws IOException {
        // 拒绝日志必须包含判定依据，便于审计与测试核对
        log.info("判定结论: DENIED status={} reason={} detail={} method={} path={}",
                status, reason, detail, request.getMethod(), request.getRequestURI());
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(MAPPER.writeValueAsString(DecisionResponse.denied(reason, detail)));
    }
}
