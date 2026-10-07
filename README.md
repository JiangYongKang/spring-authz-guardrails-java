# spring-authz-guardrails-java

一套**不依赖外部身份服务**的认证、授权与访问限流能力，基于 Spring Boot 3 / Java 21，
仅使用 JDK 与工程已有依赖（spring-boot-starter-web / test），全部状态保存在进程内存中。

## 能力总览

| 能力 | 组件 | 说明 |
| --- | --- | --- |
| 凭据校验 | `auth/CredentialStore` | 内存账号库，口令以 SHA-256(盐+口令) 保存，常量时间比较 |
| 令牌签发/校验/失效 | `auth/TokenService` | HMAC-SHA256 自包含令牌，支持单令牌撤销与主体级注销 |
| 会话续期 | `auth/RefreshTokenService` | 长效续期凭据，一次性轮换，注销即时失效 |
| 授权判定 | `authz/AuthorizationService` | 角色→权限静态映射，纯函数判定，并发下结果一致 |
| 访问限流 | `ratelimit/RateLimiter` | 按主体固定窗口计数，窗口滚动自动恢复；业务接口与认证入口各一套、互不影响 |
| 请求拦截 | `web/AuthInterceptor` | 固定顺序：限流 → 认证 → 授权，拒绝即写回可区分结论 |

## 令牌规则

- 结构：`base64url(header).base64url(payload).base64url(HMAC-SHA256签名)`。
- payload 声明：`sub`（主体）、`perms`（权限，逗号分隔）、`iat`（签发秒）、`exp`（过期秒）、
  `jti`（唯一编号）、`se`（主体纪元号，注销即递增，用于主体级失效判定）。
- 有效期由 `security.token.ttl-seconds` 控制（默认 300 秒）；签名密钥随进程启动随机生成，重启即全部失效。
- 校验顺序固定：**结构/签名 → 撤销 → 过期**，拒绝原因两两可区分：

| HTTP | reason | 含义 |
| --- | --- | --- |
| 401 | `TOKEN_MISSING` | 未提供令牌 |
| 401 | `TOKEN_TAMPERED` | 格式非法或签名不匹配（被篡改/伪造） |
| 401 | `TOKEN_EXPIRED` | 已过期 |
| 401 | `TOKEN_REVOKED` | 已被撤销（注销或主动失效） |
| 401 | `BAD_CREDENTIALS` | 登录时用户名或口令错误 |

- **注销立即生效**：`POST /auth/logout` 将该主体的纪元号（`se` 声明）递增，此前签发的令牌
  纪元不再匹配、一律以 `TOKEN_REVOKED` 拒绝；注销后立刻重新登录（即使同一秒内）签发的
  新令牌使用新纪元，可立即使用；已撤销的令牌不会因重新登录而复效。

## 会话续期

长时间在线的客户端无需反复输入口令：登录时除访问令牌外还会签发一份**续期凭据**
（`refreshToken` 字段），访问令牌快到期或刚过期不久时，凭它换新令牌即可。

- 端点：`POST /auth/refresh`，请求体 `{"refreshToken":"..."}`；
  成功返回新的访问令牌 + **新的续期凭据** + 主体。
- 结构与访问令牌相同（三段 HMAC-SHA256），但使用**独立签名密钥**且携带 `typ=refresh`
  声明：续期凭据不能当访问令牌用，访问令牌也不能当续期凭据用。
- 有效期由 `security.refresh.ttl-seconds` 控制（默认 604800 秒 = 7 天），与访问令牌
  的 TTL 相互独立。
- **轮换规则**：每次续期成功都换发一份新续期凭据，旧凭据当场作废（一次性使用）。
  同一份旧凭据并发重复提交时，原子占位保证**最多只有一次成功**，其余以
  `REFRESH_TOKEN_REVOKED` 拒绝，且不会因此多出可用凭据。
- 换发的访问令牌权限快照自登录时刻，与原登录主体保持一致：不降权、不越权。
- 续期失败原因与访问令牌失败原因两两可区分：

| HTTP | reason | 含义 |
| --- | --- | --- |
| 401 | `REFRESH_TOKEN_MISSING` | 未提供续期凭据 |
| 401 | `REFRESH_TOKEN_TAMPERED` | 格式非法/签名不匹配（被篡改），或拿访问令牌冒充 |
| 401 | `REFRESH_TOKEN_EXPIRED` | 续期凭据自身已过期 |
| 401 | `REFRESH_TOKEN_REVOKED` | 已注销、已轮换作废或被重复使用 |

- **注销的即时语义与兼容范围**：注销同时撤销该主体的全部访问令牌与续期凭据
  （两边都按主体纪元号判定），立即生效；其它主体的会话不受牵连；
  注销后立刻重新登录拿到的全新令牌与续期凭据可立即正常使用；
  已撤销的凭据不会因为之后重新登录而复效。

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

系统有**两套相互独立**的限流器，状态互不牵连：

**业务接口限流**（`/api/**`，由 `AuthInterceptor` 执行）：

- 按主体统计：已认证请求按用户名（`sub:xxx`），未认证请求按来源地址（`ip:xxx`）。
- 固定窗口计数：窗口长度 `ratelimit.window-millis`（默认 60000ms），
  每窗口最多 `ratelimit.max-requests` 次访问（默认 20）。
- 失败尝试（认证/授权失败）单独计数，超过 `ratelimit.max-failures`（默认 5）同样触发限制。

**认证入口限流**（`/auth/login` 与 `/auth/refresh`，由 `AuthController` 执行）：

- 登录按用户名（`login:xxx`）统计失败尝试；续期按来源地址（`refresh:xxx`）统计
  （凭据可能被篡改，其声明的主体不可信）。
- 参数独立配置：`ratelimit.auth.window-millis`（默认 60000ms）、
  `ratelimit.auth.max-requests`（默认 100）、`ratelimit.auth.max-failures`（默认 5）。
- 反复输错口令、反复提交无效续期凭据都会被统计；达到阈值后在窗口内被拒绝，
  窗口推移自动恢复，恢复后成功登录/续期即可正常继续。

**公共规则**：

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
# 构建并运行全部测试（56 项：令牌过期/篡改/注销/续期轮换/并发/限流恢复等）
mvn test

# 本地启动（随机端口，也可在 application.properties 固定端口）
mvn spring-boot:run
```

手工验证示例（假设端口 8080）：

```bash
# 登录拿令牌 + 续期凭据
RESP=$(curl -s -X POST localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}')
TOKEN=$(echo "$RESP" | jq -r .token)
REFRESH=$(echo "$RESP" | jq -r .refreshToken)

# 正常访问
curl -s localhost:8080/api/resource -H "Authorization: Bearer $TOKEN"

# 续期：不换口令换新令牌，同时换发新续期凭据（旧凭据当场作废）
RESP2=$(curl -s -X POST localhost:8080/auth/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}")
TOKEN2=$(echo "$RESP2" | jq -r .token)
curl -s localhost:8080/api/resource -H "Authorization: Bearer $TOKEN2"

# 旧续期凭据重复使用 → 401 REFRESH_TOKEN_REVOKED
curl -s -X POST localhost:8080/auth/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}"

# 越权（alice 无 ADMIN_OPERATE）→ 403 PERMISSION_DENIED
curl -s localhost:8080/api/admin/stats -H "Authorization: Bearer $TOKEN2"

# 注销后访问令牌与续期凭据都立即失效 → 401 TOKEN_REVOKED / REFRESH_TOKEN_REVOKED
curl -s -X POST localhost:8080/auth/logout -H "Authorization: Bearer $TOKEN2"
curl -s localhost:8080/api/resource -H "Authorization: Bearer $TOKEN2"
```

## 测试说明

- `TokenServiceTest`：过期、篡改（伪造 payload / 错误密钥）、撤销、注销后全量失效、跨主体隔离。
- `RefreshTokenServiceTest`：续期轮换成功、过期/篡改/错误密钥/访问令牌冒充、一次性消费、
  注销即时失效、注销后立刻重登可用且旧凭据不复效、跨主体隔离、并发轮换仅一次成功。
- `RateLimiterTest`：阈值触发、窗口滚动自动恢复、失败计数限流、主体间隔离、并发下放行总数恒定。
- `GuardrailsIntegrationTest`：全链路 401/403/429 可区分、越权零副作用、并发判定一致性、
  限流触发与自动恢复。
- `RefreshFlowIntegrationTest`：续期全链路——登录签发续期凭据、续期成功且权限不降不越、
  访问令牌过期后仍可续期、续期凭据过期/篡改/撤销/缺失各原因可区分、一次性与并发轮换、
  注销同时撤销访问令牌与续期凭据、注销后立刻重登可用、跨主体隔离。
- `AuthEntryRateLimitTest`：登录/续期入口失败限流——反复失败触发 429、窗口推移自动恢复、
  按用户名/来源地址隔离、与业务接口限流互不牵连。
- 所有被拒绝的请求都会在测试日志中打印判定依据（`判定结论: DENIED status=... reason=...`），
  可直接核对拒绝原因；测试通过可注入的 `MutableClock` 模拟时间推移，无需真实等待。
