package com.github.highcumontoa.springauthzguardrailsjava.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 受保护资源端点。
 * 写操作维护一个内存计数器作为"可观测副作用"：越权请求被拦截器拒绝后，
 * 计数器必须保持不变，以此验证"无权操作不产生任何副作用"。
 */
@RestController
@RequestMapping("/api")
public class ResourceController {

    private final Map<String, AtomicLong> writeCounts = new ConcurrentHashMap<>();

    @GetMapping("/resource")
    public Map<String, Object> read(HttpServletRequest request) {
        AuthContext ctx = (AuthContext) request.getAttribute(AuthInterceptor.ATTR_AUTH_CONTEXT);
        return Map.of(
                "decision", "ALLOWED",
                "subject", ctx.subject(),
                "data", "resource-content");
    }

    @PostMapping("/resource")
    public Map<String, Object> write(HttpServletRequest request) {
        AuthContext ctx = (AuthContext) request.getAttribute(AuthInterceptor.ATTR_AUTH_CONTEXT);
        long count = writeCounts.computeIfAbsent(ctx.subject(), k -> new AtomicLong())
                .incrementAndGet();
        return Map.of(
                "decision", "ALLOWED",
                "subject", ctx.subject(),
                "writeCount", count);
    }

    @GetMapping("/resource/write-count")
    public Map<String, Object> writeCount(HttpServletRequest request) {
        AuthContext ctx = (AuthContext) request.getAttribute(AuthInterceptor.ATTR_AUTH_CONTEXT);
        AtomicLong counter = writeCounts.get(ctx.subject());
        return Map.of(
                "subject", ctx.subject(),
                "writeCount", counter == null ? 0 : counter.get());
    }

    @GetMapping("/admin/stats")
    public Map<String, Object> adminStats(HttpServletRequest request) {
        AuthContext ctx = (AuthContext) request.getAttribute(AuthInterceptor.ATTR_AUTH_CONTEXT);
        return Map.of(
                "decision", "ALLOWED",
                "subject", ctx.subject(),
                "totalWriteSubjects", writeCounts.size());
    }
}
