package com.github.highcumontoa.springauthzguardrailsjava.authz;

import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * 授权判定：基于主体权限集合判断是否允许执行操作。
 * 纯函数、无状态、不可变输入，因此并发请求下判定结果必然一致。
 */
@Service
public class AuthorizationService {

    public boolean isAllowed(Set<String> subjectPermissions, Permission required) {
        return subjectPermissions != null && subjectPermissions.contains(required.name());
    }
}
