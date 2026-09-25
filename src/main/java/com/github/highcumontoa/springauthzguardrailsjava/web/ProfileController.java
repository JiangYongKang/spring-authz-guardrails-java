package com.github.highcumontoa.springauthzguardrailsjava.web;

import com.github.highcumontoa.springauthzguardrailsjava.domain.UserAccount;
import com.github.highcumontoa.springauthzguardrailsjava.security.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    /** 需要 profile:read 权限；所有已预置角色均具备。 */
    @GetMapping("/me")
    public Map<String, Object> me(HttpServletRequest request) {
        UserAccount user = SecurityContext.currentUser(request);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", user.getUsername());
        body.put("roles", user.getRoles());
        body.put("permissions", user.getPermissions());
        return body;
    }
}
