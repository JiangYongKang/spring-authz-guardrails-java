package com.github.highcumontoa.springauthzguardrailsjava.tests;

import com.github.highcumontoa.springauthzguardrailsjava.domain.UserAccount;
import com.github.highcumontoa.springauthzguardrailsjava.security.AuthorizationRules;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationRulesTest {

    private final AuthorizationRules rules = new AuthorizationRules();
    private final UserAccount alice = new UserAccount("alice", "p",
            Set.of("USER"), Set.of("profile:read"));
    private final UserAccount admin = new UserAccount("admin", "p",
            Set.of("USER", "ADMIN"), Set.of("profile:read"));

    @Test
    @DisplayName("具备所需权限即允许")
    void permissionMatch() {
        assertThat(rules.isAllowed(alice, "GET", "/api/profile/me")).isTrue();
    }

    @Test
    @DisplayName("已认证但缺少权限 -> 拒绝（403），与未认证区分")
    void authenticatedButForbidden() {
        assertThat(rules.isAllowed(alice, "GET", "/api/users")).isFalse();
        assertThat(rules.isAllowed(alice, "DELETE", "/api/users/bob")).isFalse();
        assertThat(rules.isAllowed(alice, "GET", "/api/admin/ping")).isFalse();
    }

    @Test
    @DisplayName("ADMIN 角色隐含全部权限")
    void adminHasAllPermissions() {
        assertThat(rules.isAllowed(admin, "GET", "/api/users")).isTrue();
        assertThat(rules.isAllowed(admin, "DELETE", "/api/users/bob")).isTrue();
        assertThat(rules.isAllowed(admin, "GET", "/api/admin/ping")).isTrue();
    }

    @Test
    @DisplayName("未认证主体（null）一律拒绝")
    void unauthenticatedRejected() {
        assertThat(rules.isAllowed(null, "GET", "/api/profile/me")).isFalse();
    }

    @Test
    @DisplayName("未声明的路径默认拒绝（fail-closed）")
    void undeclaredRouteDeniedByDefault() {
        assertThat(rules.isAllowed(admin, "GET", "/api/unknown")).isFalse();
    }

    @Test
    @DisplayName("同一路径不同方法分别授权")
    void methodSpecificAuthorization() {
        UserAccount listingAdmin = new UserAccount("lister", "p",
                Set.of("USER"), Set.of("user:list"));
        assertThat(rules.isAllowed(listingAdmin, "GET", "/api/users")).isTrue();
        assertThat(rules.isAllowed(listingAdmin, "DELETE", "/api/users/bob")).isFalse();
    }

    @Test
    @DisplayName("路径模式：删除任意用户都需要 user:delete，单段外路径不匹配")
    void pathPatternForUserDelete() {
        assertThat(rules.requiredPermission("DELETE", "/api/users/alice"))
                .isEqualTo("user:delete");
        assertThat(rules.requiredPermission("DELETE", "/api/users/a/b")).isNull();
        assertThat(rules.isAllowed(alice, "DELETE", "/api/users/alice")).isFalse();
        assertThat(rules.isAllowed(admin, "DELETE", "/api/users/anyone")).isTrue();
    }
}
