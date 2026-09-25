# spring-authz-guardrails-java

一套**不依赖外部身份服务**的认证、授权与访问限流能力，基于 Spring Boot 3 / Java 21，
仅使用 JDK 与工程已有依赖（spring-boot-starter-web / test），全部状态保存在进程内存中。

## 能力总览

| 能力 | 组件 | 说明 |
| --- | --- | --- |
| 凭据校验 | `auth/CredentialStore` | 内存账号库，口令以 SHA-256(盐+口令) 保存，常量时间比较 |
| 令牌签发/校验/失效 | `auth/TokenService` | HMAC-SHA256 自包含令牌，支持单令牌撤销与主体级注销 |
| 授权判定 | `authz/AuthorizationService` | 角色→权限静态映射，纯函数判定，并发下结果一致 |
| 访问限流 | `ratelimit/RateLimiter` | 按主体固定窗口计数，窗口滚动自动恢复 |
| 请求拦截 | `web/AuthInterceptor` | 固定顺序：限流 → 认证 → 授权，拒绝即写回可区分结论 |

## 令牌规则

- 结构：`base64url(header).base64url(payload).base64url(HMAC-SHA256签名)`。
- payload 声明：`sub`（主体）、`perms`（权限，逗号分隔）、`iat`（签发秒）、`exp`（过期秒）、`jti`（唯一编号）。
- 有效期由 `security.token.ttl-seconds` 控制（默认 300 秒）；签名密钥随进程启动随机生成，重启即全部失效。
- 校验顺序固定：**结构/签名 → 撤销 → 过期**，拒绝原因两两可区分：

| HTTP | reason | 含义 |
| --- | --- | --- |
| 401 | `TOKEN_MISSING` | 未提供令牌 |
| 401 | `TOKEN_TAMPERED` | 格式非法或签名不匹配（被篡改/伪造） |
| 401 | `TOKEN_EXPIRED` | 已过期 |
| 401 | `TOKEN_REVOKED` | 已被撤销（注销或主动失效） |
| 401 | `BAD_CREDENTIALS` | 登录时用户名或口令错误 |

- **注销立即生效**：`POST /auth/logout` 记录主体撤销时间戳，凡 `iat` 早于等于该时刻的令牌一律以
  `TOKEN_REVOKED` 拒绝；此后新签发的令牌不受影响。

## 权限模型

角色到权限为静态映射（`authz/Role`）：

| 角色 | 权限 |
| --- | --- |
| `GUEST` | `RESOURCE_READ` |
| `USER` | `RESOURCE_READ`, `RESOURCE_WRITE` |
| `ADMIN` | 以上全部 + `ADMIN_OPERATE` |

路径到权限的映射（`AuthInterceptor.requiredPermission`）：

| 路径 | 方法 | 所需权限 |
| --- | --- | --- |
| `/api/resource` | GET | `RESOURCE_READ` |
| `/api/resource` | POST/PUT/DELETE | `RESOURCE_WRITE` |
| `/api/admin/**` | 任意 | `ADMIN_OPERATE` |

- 未认证（401）与已认证但无权限（403 `PERMISSION_DENIED`）返回**不同结论**。
- 授权判定为纯函数，输入不可变，并发请求下判定结果必然一致。
- 被拒绝的请求在拦截器阶段即返回，**不会进入控制器，不产生任何副作用**
  （集成测试用写计数器验证越权后计数恒为 0）。

预置演示账号（仅本地使用，非常量真实凭据）：`alice/alice-pass`(USER)、`bob/bob-pass`(ADMIN)、`carol/carol-pass`(GUEST)。

## 限流策略

- 按主体统计：已认证请求按用户名（`sub:xxx`），未认证请求按来源地址（`ip:xxx`）。
- 固定窗口计数：窗口长度 `ratelimit.window-millis`（默认 60000ms），
  每窗口最多 `ratelimit.max-requests` 次访问（默认 20）。
- 失败尝试（认证/授权失败）单独计数，超过 `ratelimit.max-failures`（默认 5）同样触发限制。
- 超限返回 **429 `RATE_LIMITED`**，响应体附带 `retryAfter` 提示；窗口随时间推移自动滚动，计数清零即**自动恢复**。
- 判定顺序为限流 → 认证 → 授权，因此 429 / 401 / 403 互不掩盖；响应体 `reason` 字段始终可区分。
- 状态变更通过 `ConcurrentHashMap.compute` 原子完成，并发下放行总数恒等于阈值（有并发测试保证）。

统一响应体：

```json
{ "decision": "DENIED", "reason": "TOKEN_EXPIRED", "detail": "令牌已过期" }
```

所有拒绝均打印判定依据日志，例如：

```
判定结论: DENIED status=401 reason=TOKEN_REVOKED detail=令牌已被撤销（注销或主动失效） method=GET path=/api/resource
```

## 本地验证

```bash
# 构建并运行全部测试（27 项：令牌过期/篡改/注销/越权/并发/限流恢复等）
mvn test

# 本地启动（随机端口，也可在 application.properties 固定端口）
mvn spring-boot:run
```

手工验证示例（假设端口 8080）：

```bash
# 登录拿令牌
TOKEN=$(curl -s -X POST localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}' | jq -r .token)

# 正常访问
curl -s localhost:8080/api/resource -H "Authorization: Bearer $TOKEN"

# 越权（alice 无 ADMIN_OPERATE）→ 403 PERMISSION_DENIED
curl -s localhost:8080/api/admin/stats -H "Authorization: Bearer $TOKEN"

# 注销后令牌立即失效 → 401 TOKEN_REVOKED
curl -s -X POST localhost:8080/auth/logout -H "Authorization: Bearer $TOKEN"
curl -s localhost:8080/api/resource -H "Authorization: Bearer $TOKEN"
```

## 测试说明

- `TokenServiceTest`：过期、篡改（伪造 payload / 错误密钥）、撤销、注销后全量失效、跨主体隔离。
- `RateLimiterTest`：阈值触发、窗口滚动自动恢复、失败计数限流、主体间隔离、并发下放行总数恒定。
- `GuardrailsIntegrationTest`：全链路 401/403/429 可区分、越权零副作用、并发判定一致性、
  限流触发与自动恢复；测试通过可注入的 `MutableClock` 模拟时间推移，无需真实等待。
