package com.github.highcumontoa.springauthzguardrailsjava.domain;

import java.util.Set;

public class UserAccount {

    private final String username;
    private final String password;
    private final Set<String> roles;
    private final Set<String> permissions;

    public UserAccount(String username, String password, Set<String> roles, Set<String> permissions) {
        this.username = username;
        this.password = password;
        this.roles = roles;
        this.permissions = permissions;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public Set<String> getPermissions() {
        return permissions;
    }
}
