# spring-authz-guardrails-java

一套**不依赖外部身份服务**的认证、授权与访问限流能力，基于 Spring Boot 3 / Java 21，
仅使用 JDK 与工程已有依赖（spring-boot-starter-web / test），全部状态保存在进程内存中。

## 能力总览

| 能力 | 组件 | 说明 |
| --- | --- | --- |
| 凭据校验 | `auth/CredentialStore` | 内存账号库，口令以 SHA-256(盐+口令) 保存，常量时间比较 |
| 访问令牌签发/校验/失效 | `auth/TokenService` | HMAC-SHA256 自包含令牌，支持单令牌撤销与主体级注销（注销代号） |
| 续期凭据与轮换 | `auth/RefreshTokenService` | 长期凭据换发新访问令牌，一次性轮换、原子防重放、主体级撤销 |
| 授权判定 | `authz/AuthorizationService` | 角色→权限静态映射，纯函数判定，并发下结果一致 |
| 访问限流 | `ratelimit/RateLimiter` | 固定窗口计数，业务接口与认证入口各一个独立实例，窗口滚动自动恢复 |
| 请求拦截 | `web/AuthInterceptor` | 固定顺序：限流 → 认证 → 授权，拒绝即写回可区分结论 |

## 令牌与续期规则

- 结构（访问令牌与续期凭据相同）：`base64url(header).base64url(payload).base64url(HMAC-SHA256签名)`。
- 两类凭据使用**相互独立的随机签名密钥**；续期凭据 payload 含 `"kind":"refresh"` 与 `gen`（注销代号），
  访问令牌不能冒充续期凭据，反之亦然；签名密钥随进程启动随机生成，重启即全部失效。
- 访问令牌 payload：`sub`、`perms`、`iat`、`exp`、`rvv`（签发时注销代号）、`jti`。
- 续期凭据 payload：`sub`、`kind=refresh`、`iat`、`exp`、`gen`、`jti`。
- 有效期：访问令牌 `security.token.ttl-seconds`（默认 300 秒）；
  续期凭据 `security.refresh-token.ttl-seconds`（默认 1209600 秒 = 14 天）。
- 访问令牌校验顺序固定：**结构/签名 → 撤销 → 过期**，拒绝原因两两可区分：

| HTTP | reason | 含义 |
| --- | --- | --- |
| 401 | `TOKEN_MISSING` | 未提供令牌 |
| 401 | `TOKEN_TAMPERED` | 格式非法或签名不匹配（被篡改/伪造） |
| 401 | `TOKEN_EXPIRED` | 已过期 |
| 401 | `TOKEN_REVOKED` | 已被撤销（注销或主动失效） |
| 401 | `BAD_CREDENTIALS` | 登录时用户名或口令错误 |

### 续期（refresh）使用场景

- 客户端在访问令牌快到期、或刚过期后，凭续期凭据调用 `POST /auth/refresh` 即可换发新令牌，
  **无需再次输入口令**。
- 响应同时返回新的访问令牌 `token` 和新的续期凭据 `refreshToken`；新访问令牌立即可用，
  其权限在续期时**从账号库按主体重新读取**，与原登录主体保持一致——不降权、不越权
  （篡改声明会因签名不符被拒）。

### 轮换（rotation）规则

- 每次续期成功都**当场作废旧续期凭据**并换发一份新的；旧凭据再次提交得到 `401 REFRESH_USED`。
- 作废通过对 `jti` 的**原子**登记完成，同一凭据并发提交**至多一次成功**，
  失败请求不会产生任何新凭据（有并发测试保证）。
- 续期凭据校验顺序固定：**结构/签名 → 过期 → 注销代号 → 是否已轮换**，失败原因两两可区分：

| HTTP | reason | 含义 |
| --- | --- | --- |
| 401 | `REFRESH_MISSING` | 未提供续期凭据 |
| 401 | `REFRESH_TAMPERED` | 格式非法/签名不匹配（被篡改），或误把访问令牌当作续期凭据 |
| 401 | `REFRESH_EXPIRED` | 续期凭据已过期 |
| 401 | `REFRESH_REVOKED` | 续期凭据已被撤销（主体注销，或主体已不可用） |
| 401 | `REFRESH_USED` | 续期凭据已被轮换使用（旧凭据重放，含并发重放） |

这些原因与访问令牌的 `TOKEN_*`、未认证、无权限 `PERMISSION_DENIED`、限流 `*_RATE_LIMITED`
**全部互不相同**，不会混在一起。

- **注销立即生效（即时语义）**：`POST /auth/logout` 让主体的“注销代号”在访问令牌服务与
  续期凭据服务中**同时前进一步**。此后：
  - 该主体此前拿到的**所有访问令牌**一律以 `TOKEN_REVOKED` 拒绝；
  - 此前拿到的**所有续期凭据**一律以 `REFRESH_REVOKED` 拒绝，不能再换发新令牌；
  - 其它主体的会话**不受牵连**。
- **注销后立刻重新登录**：新令牌/新续期凭据携带新代号，**不推进时钟也立即判为有效**，
  不会出现“刚登录就失效”（代号方案取代了旧的秒级时间戳比较，规避了同一秒注销+登录的误伤）。
- **代号单调递增、只增不减**：重新登录不会让已撤销的旧凭据复活；旧访问令牌/旧续期凭据
  在此后任何时刻仍然是撤销结论。
- **兼容范围**：注销为主体级语义（同一用户的全部会话同时失效）；不含跨设备选择性注销、
  会话列表查询或服务端持久化（状态仍只保存在进程内存，重启即清空）。

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

系统中有**两个相互独立**的 `RateLimiter` 实例，窗口与计数互不牵连：

| 实例 | 覆盖入口 | 统计键 | 阈值配置 | 超限结论 |
| --- | --- | --- | --- | --- |
| `apiRateLimiter` | `/api/**` 业务接口 | 已认证按 `sub:用户名`，未认证按 `ip:地址` | `ratelimit.*` | 429 `RATE_LIMITED` |
| `authRateLimiter` | `/auth/login`、`/auth/refresh` | 登录按 `login:用户名`，续期按 `refresh-ip:地址` | `ratelimit.auth.*` | 429 `LOGIN_RATE_LIMITED` / `REFRESH_RATE_LIMITED` |

- 固定窗口计数：窗口长度可配，窗口内访问次数达 `max-requests`、或失败尝试累计达 `max-failures`
  即触发限制；窗口随时间推移自动滚动，计数清零即**自动恢复**。
- 反复输错口令、反复提交无效续期凭据都会被统计；**成功一次即清空该键的失败计数**，
  随后正常使用不再受此前失败牵连。
- 业务接口被限流不会影响登录/续期，反之亦然（有测试保证独立性）。
- 任一入口被限流的结论都与 401（各类凭据失效）、403（无权限）**可区分**，响应体 `reason` 互不掩盖。
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
# 构建并运行全部测试（53 项：令牌/续期过期、篡改、撤销、一次性并发轮换、
# 注销后立即重登、越权、业务/认证入口限流与自动恢复等）
mvn test

# 本地启动（随机端口，也可在 application.properties 固定端口）
mvn spring-boot:run
```

手工验证示例（假设端口 8080）：

```bash
# 登录：响应同时含访问令牌 token 与续期凭据 refreshToken
LOGIN=$(curl -s -X POST localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}')
TOKEN=$(echo "$LOGIN" | jq -r .token)
REFRESH=$(echo "$LOGIN" | jq -r .refreshToken)

# 正常访问
curl -s localhost:8080/api/resource -H "Authorization: Bearer $TOKEN"

# 访问令牌过期后免口令续期：返回新的 token + 新的 refreshToken，旧 REFRESH 当场作废
curl -s -X POST localhost:8080/auth/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}"

# 旧续期凭据重放 -> 401 REFRESH_USED
curl -s -X POST localhost:8080/auth/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}"

# 越权（alice 无 ADMIN_OPERATE）→ 403 PERMISSION_DENIED
curl -s localhost:8080/api/admin/stats -H "Authorization: Bearer $TOKEN"

# 注销后访问令牌与续期凭据立即失效；立即重新登录拿到的新凭据马上可用
curl -s -X POST localhost:8080/auth/logout -H "Authorization: Bearer $TOKEN"
curl -s localhost:8080/api/resource -H "Authorization: Bearer $TOKEN"   # 401 TOKEN_REVOKED
```

## 测试说明

- `TokenServiceTest`：访问令牌过期、篡改（伪造 payload / 错误密钥）、撤销、注销后全量失效、
  **同一秒内注销+重新登录旧令牌仍撤销且新令牌有效**、跨主体隔离。
- `RefreshTokenServiceTest`：续期成功与代号返回；缺失/畸形/错签名/篡改 payload 拒绝；
  访问令牌不能冒充续期凭据；过期、注销撤销、重新登录不复活旧凭据；一次性轮换、
  **24 线程并发重放恰一次成功**；跨主体隔离。
- `RateLimiterTest`：阈值触发、窗口滚动自动恢复、失败计数限流、主体间隔离、并发下放行总数恒定。
- `GuardrailsIntegrationTest`：全链路 401/403/429 可区分；续期成功且权限不升降、
  续期凭据过期/篡改/缺失/撤销/已轮换结论可区分；轮换旧凭据当场作废与并发重放；
  **注销后不推进时间立即重新登录可用**、其它主体不受牵连；登录/续期入口失败限流与自动恢复、
  认证入口限流与业务限流相互独立；越权零副作用；测试通过可注入的 `MutableClock` 模拟时间推移。
- 每个被拒绝的请求都会打印判定依据日志，例如：

```text
判定结论: DENIED status=401 reason=REFRESH_USED detail=续期凭据已被轮换使用（旧凭据重放） ip=127.0.0.1
判定结论: DENIED status=429 reason=LOGIN_RATE_LIMITED detail=登录失败尝试超过阈值，...ms 后窗口滚动自动恢复 username=alice
```
