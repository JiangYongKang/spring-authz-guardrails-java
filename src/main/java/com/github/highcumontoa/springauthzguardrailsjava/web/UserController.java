package com.github.highcumontoa.springauthzguardrailsjava.web;

import com.github.highcumontoa.springauthzguardrailsjava.security.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    /** 需要 user:list 权限，仅 ADMIN 具备。 */
    @GetMapping
    public Map<String, Object> list(HttpServletRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("operator", SecurityContext.currentUser(request).getUsername());
        body.put("users", java.util.List.of("alice", "bob", "admin"));
        return body;
    }

    /** 需要 user:delete 权限，仅 ADMIN 具备；无权时在过滤器即被拒绝，不会执行到这里。 */
    @DeleteMapping("/{username}")
    public Map<String, Object> delete(HttpServletRequest request,
                                      @PathVariable String username) {
        return Map.of(
                "operator", SecurityContext.currentUser(request).getUsername(),
                "deleted", username,
                "sideEffectApplied", true
        );
    }
}
