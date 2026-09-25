package com.github.highcumontoa.springauthzguardrailsjava.web;

import com.github.highcumontoa.springauthzguardrailsjava.domain.UserAccount;
import com.github.highcumontoa.springauthzguardrailsjava.security.AuthService;
import com.github.highcumontoa.springauthzguardrailsjava.security.SecurityContext;
import com.github.highcumontoa.springauthzguardrailsjava.security.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * 公开接口：凭据换取访问令牌。
     * 凭据错误与失败尝试超限分别返回 BAD_CREDENTIALS / LOGIN_RATE_LIMITED。
     */
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest request) {
        TokenService.IssuedToken issued = authService.login(request.username(), request.password());
        return Map.of(
                "accessToken", issued.token(),
                "tokenType", "Bearer",
                "expiresAt", issued.expiresAtEpochSeconds()
        );
    }

    /**
     * 需认证：注销当前令牌；all=true 时撤销该主体全部已签发令牌（多端登出）。
     */
    @PostMapping("/logout")
    public Map<String, Object> logout(HttpServletRequest request,
                                      @RequestParam(name = "all", defaultValue = "false") boolean all) {
        UserAccount user = SecurityContext.currentUser(request);
        authService.logout(user, SecurityContext.currentToken(request), all);
        return Map.of("status", "logged-out", "scope", all ? "ALL" : "CURRENT");
    }

    public record LoginRequest(String username, String password) {
    }
}
