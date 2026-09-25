# Spring Authz Guardrails（本地认证、授权与访问限流）

一套**完全本地化、不依赖任何外部身份服务**的认证（Authentication）、授权（Authorization）
与访问限流（Rate Limiting）护栏能力。所有令牌均由本服务签发与校验，用户数据保存在内存中，
无需数据库、Redis 或第三方凭据，可直接在本地构建与运行。

## 1. 能力概览

| 能力 | 说明 |
| --- | --- |
| 凭据校验 | 内存用户目录，用户名 + 密码（演示用明文）校验，校验失败与失败限流原因可区分 |
| 令牌签发 | 登录成功后签发自包含访问令牌（HMAC-SHA256 签名），携带主体、签发/过期时间与唯一 ID |
| 令牌校验 | 缺失 / 格式损坏 / 签名被篡改 / 已过期 / 已撤销，五类拒绝原因**互不相同** |
| 主动失效 | 注销单个令牌立即失效；`all=true` 可令该主体全部已签发令牌立即失效 |
| 授权 | 按「HTTP 方法 + 路径」映射到所需权限；未认证 401 与已认证无权 403 结论不同 |
| 无副作用 | 无权请求在过滤器层即被拒绝，不会进入控制器、不产生任何副作用 |
| 访问限流 | 按主体在滑动时间窗口内统计请求，超阈值返回 429，窗口推移后自动恢复 |
| 登录失败限流 | 按主体统计窗口内失败尝试，超阈值即使密码正确也被拒绝（独立于访问限流） |
| 并发一致 | 限流器按 key 加锁 + 滑动窗口，并发下放行数量严格等于阈值 |
| 可解释 | 每个拒绝响应都带 `reason` 与 `message`，并在日志打印被拒绝请求的判定依据 |

## 2. 令牌规则

### 2.1 格式

```
base64url(username | issuedAt | expiresAt | jti)  .  hex(HMAC_SHA256(payload, secret))
```

- `jti`：每个令牌的随机唯一 ID；
- 签名密钥通过 `guardrail.token.hmac-key` 配置（**生产环境必须用环境变量覆盖默认值**）；
- 签名比较使用常量时间比较，避免计时侧信道。

### 2.2 校验顺序（原因可区分）

| 顺序 | 情形 | HTTP | `reason` |
| --- | --- | --- | --- |
| 1 | 无 `Authorization: Bearer` 头 | 401 | `MISSING_TOKEN` |
| 2 | 令牌不是 `payload.signature` 两段式 / 无法解码 | 401 | `MALFORMED_TOKEN` |
| 3 | 签名与重算结果不一致（载荷或签名被篡改、密钥不同） | 401 | `SIGNATURE_INVALID` |
| 4 | 当前时间 ≥ `expiresAt` | 401 | `TOKEN_EXPIRED` |
| 5 | 令牌已被注销（单令牌 / 批量注销） | 401 | `TOKEN_REVOKED` |
| 6 | 令牌对应主体不存在 | 401 | `MALFORMED_TOKEN` |

> 注意过期判定先于撤销判定：已过期且已注销的令牌返回 `TOKEN_EXPIRED`，原因仍然唯一确定。

### 2.3 注销语义

- `POST /api/auth/logout`：只撤销当前这一枚令牌；
- `POST /api/auth/logout?all=true`：撤销当前主体在此之前签发的**所有**令牌
  （实现上同时维护 jti 黑名单与「批量注销时间点」，注销后重新登录签发的新令牌不受影响）；
- 注销是同步生效的，注销响应返回后该令牌再次使用立即得到 `TOKEN_REVOKED`。

## 3. 权限模型

- **角色 ROLE（粗粒度）**：`USER`、`ADMIN`；`ADMIN` 隐含全部权限。
- **权限 PERMISSION（细粒度）**：形如 `资源:动作`，授权以权限为直接判定依据。
- **路由表**（未声明的路径一律默认拒绝 fail-closed；`*` 匹配单段路径）：

| 方法 | 路径 | 所需权限 |
| --- | --- | --- |
| POST | `/api/auth/login` | 公开（无需令牌） |
| POST | `/api/auth/logout` | 仅需已认证（`*`） |
| GET | `/api/profile/me` | `profile:read` |
| GET | `/api/users` | `user:list` |
| DELETE | `/api/users/{username}` | `user:delete` |
| GET | `/api/admin/ping` | `admin:read` |

预置用户（仅本地演示）：

| 用户名 | 密码 | 角色 | 权限 |
| --- | --- | --- | --- |
| `alice` | `password-alice` | USER | `profile:read` |
| `bob` | `password-bob` | USER | `profile:read` |
| `admin` | `password-admin` | USER, ADMIN | 全部 |

### 判定流水线（`GuardrailFilter`，顺序固定）

```
请求
 ├─ 公开路径(/api/auth/login) ───────────────► 放行到控制器
 └─ ① 认证：令牌校验
        失败 → 401（MISSING/MALFORMED/SIGNATURE/EXPIRED/REVOKED）
     ② 访问限流：按主体滑动窗口（仅统计通过认证的请求）
        超限 → 429 ACCESS_RATE_LIMITED
     ③ 授权：方法+路径 → 所需权限
        无权 → 403 ACCESS_DENIED（控制器不执行，无副作用）
     全部通过 → 注入当前主体，进入控制器
```

认证先于限流（未认证没有主体可统计）；限流先于授权（保证三类原因不相互掩盖）。
因此：**401（未认证）/ 403（已认证无权）/ 429（限流）三者语义和 `reason` 都严格可区分。**

## 4. 限流策略

两套互相独立的滑动窗口限流器（`SlidingWindowRateLimiter`）：

| 限流器 | key | 统计对象 | 默认阈值 | 窗口 | 超限结果 |
| --- | --- | --- | --- | --- | --- |
| 访问限流 | `access:<用户名>` | 通过认证的请求（每次 +1） | 10 次 | 60 秒 | 429 `ACCESS_RATE_LIMITED` |
| 登录失败限流 | `login:<用户名>` | 失败登录尝试 | 5 次失败 | 300 秒 | 429 `LOGIN_RATE_LIMITED` |

- 滑动窗口：每个 key 维护时间戳队列，仅保留窗口内记录；旧记录随时间滑出后**自动恢复**配额；
- 被拒绝（429/401/403）的请求**不占用**访问配额，不会把窗口「续命」；
- 登录成功会清空该主体的失败计数；失败窗口超限时即使给出正确密码也返回 429；
- 所有读写在「同一 key 的队列锁」内完成，并发下成功数严格等于阈值（有并发测试验证）。

### 配置项（`application.properties`）

```properties
guardrail.token.ttl-seconds=60                       # 令牌有效期
guardrail.token.hmac-key=local-dev-only-...          # HMAC 密钥（生产用环境变量覆盖）
guardrail.rate-limit.access-limit=10                 # 每主体窗口内访问上限
guardrail.rate-limit.window-seconds=60               # 访问窗口
guardrail.rate-limit.login-failure-limit=5           # 每主体窗口内登录失败上限
guardrail.rate-limit.login-window-seconds=300        # 登录失败窗口
```

## 5. 本地验证方法

要求：JDK 21、Maven 3.6+。

### 5.1 构建与测试

```bash
mvn clean test         # 运行全部 40 个测试（单元 + 端到端）
mvn package            # 打包可执行 jar
```

测试覆盖（拒绝时日志会以 WARN 打印 `subject / method / path / status / reason / basis`）：

- 令牌：正常签发、**过期**、载荷篡改、签名篡改、格式损坏、注销立即失效、批量注销、不同密钥互斥；
- 授权：权限匹配、已认证越权、未认证拒绝、ADMIN 全通、未声明路径 fail-closed、按方法区分；
- 限流：阈值边界、窗口自动恢复、不同 key 独立、**100 并发下恰好放行阈值数量**；
- 登录：错误凭据 vs 失败限流原因可区分、成功登录重置计数、按主体独立；
- 端到端：真实 HTTP 验证 401/403/429 的状态码与 `reason`，以及越权 DELETE 不产生副作用。

### 5.2 启动与手工验证

```bash
java -jar target/spring-authz-guardrails-java-1.0-SNAPSHOT.jar --server.port=8088
```

```bash
# 1) 登录换令牌
curl -s -X POST localhost:8088/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password-alice"}'

# 2) 带令牌访问
curl -s -H "Authorization: Bearer <TOKEN>" localhost:8088/api/profile/me

# 3) 未认证 -> 401 MISSING_TOKEN
curl -s localhost:8088/api/profile/me

# 4) 篡改令牌 -> 401 SIGNATURE_INVALID
curl -s -H "Authorization: Bearer <TOKEN 末字符改掉>" localhost:8088/api/profile/me

# 5) alice 越权 -> 403 ACCESS_DENIED（不进入控制器，无副作用）
curl -s -H "Authorization: Bearer <TOKEN>" localhost:8088/api/users

# 6) 注销，随后重放 -> 401 TOKEN_REVOKED
curl -s -X POST -H "Authorization: Bearer <TOKEN>" localhost:8088/api/auth/logout

# 7) 连续访问超过 10 次 -> 第 11 次起 429 ACCESS_RATE_LIMITED，等待 60 秒窗口滑过自动恢复
```

统一错误响应体：

```json
{ "reason": "ACCESS_DENIED", "message": "无权访问 GET /api/users，所需权限=user:list", "status": 403 }
```

## 6. 工程结构

```
src/main/java/com/github/highcumontoa/springauthzguardrailsjava/
├── config/   GuardrailProperties（配置绑定）、GuardrailConfig（限流器/过滤器 Bean）
├── domain/   UserAccount（用户名、密码、角色、权限）
├── store/    UserDirectory（内存用户目录，预置三个演示用户）
├── security/
│   ├── RejectionReason          拒绝原因枚举（9 种，互不掩盖）
│   ├── AccessDecision           认证/授权判定结果
│   ├── TokenService             令牌服务接口
│   ├── HmacTokenService         HMAC 令牌签发/校验/撤销实现
│   ├── SlidingWindowRateLimiter 线程安全滑动窗口限流器
│   ├── AuthService              凭据校验、登录失败限流、注销
│   ├── AuthorizationRules       方法+路径 → 权限 规则表
│   ├── GuardrailFilter          认证→限流→授权 统一守卫过滤器
│   ├── GuardrailRejectionException / SecurityContext
└── web/      Auth/Profile/User/Admin 控制器、ApiError、GlobalExceptionHandler
```

## 7. 设计说明与边界

- 本项目为**本地护栏演示**：密码为明文存储比对，生产应替换为加盐哈希（如 BCrypt）；
  HMAC 密钥应来自环境变量/密钥管理；撤销状态在单机内存中，多实例部署需换共享存储。
- 令牌为不透明的自包含签名令牌（非 JWT），不含敏感信息，仅含主体名与时间戳。
- 访问限流按「主体」而非 IP 统计，避免共享 NAT 误伤；未认证请求不纳入访问限流。
