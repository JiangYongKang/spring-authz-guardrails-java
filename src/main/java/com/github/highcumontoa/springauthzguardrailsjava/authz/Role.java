package com.github.highcumontoa.springauthzguardrailsjava.authz;

import java.util.Set;

/**
 * 角色到权限的静态映射。
 */
public enum Role {
    USER(Set.of(Permission.RESOURCE_READ.name(), Permission.RESOURCE_WRITE.name())),
    ADMIN(Set.of(Permission.RESOURCE_READ.name(), Permission.RESOURCE_WRITE.name(),
            Permission.ADMIN_OPERATE.name())),
    GUEST(Set.of(Permission.RESOURCE_READ.name()));

    private final Set<String> permissions;

    Role(Set<String> permissions) {
        this.permissions = permissions;
    }

    public Set<String> permissions() {
        return permissions;
    }
}
