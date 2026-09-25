package com.github.highcumontoa.springauthzguardrailsjava.web;

import com.github.highcumontoa.springauthzguardrailsjava.security.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    /** 需要 admin:read 权限，仅 ADMIN 具备。 */
    @GetMapping("/ping")
    public Map<String, Object> ping(HttpServletRequest request) {
        return Map.of(
                "pong", true,
                "operator", SecurityContext.currentUser(request).getUsername()
        );
    }
}
