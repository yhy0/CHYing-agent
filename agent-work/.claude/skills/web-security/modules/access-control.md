# Access Control Penetration Testing Patterns

当对 Web 应用进行访问控制和权限提升渗透测试时加载此 Skill。覆盖垂直/水平越权、多租户隔离绕过等。

> **与其他 Skill 的关系**：本 Skill 聚焦**授权层面**的访问控制（谁能访问什么资源）。对象级授权（IDOR）详见 `pentest-idor`，认证绕过（登录/OTP/2FA）详见 `pentest-auth-bypass`。

## Attack Surface Discovery

**高风险功能区域：**
- 管理后台：`/admin`、`/dashboard`、`/management` 路径
- 用户角色管理：角色分配、权限修改接口
- 多租户系统：组织/团队切换、跨租户数据访问
- SSO/SAML/OAuth 集成：认证断言处理、签名验证
- 密码重置/账户恢复流程
- API 端点：缺少认证中间件的端点
- OTP/验证码机制：验证逻辑、速率限制

**识别信号：**
- 前端隐藏但后端存在的管理接口（JS 代码中的路由定义）
- 不同角色响应内容的差异（管理员看到更多字段）
- API 文档中标注 "admin only" 但实际未校验的端点
- 测试环境/调试端点遗留在生产环境

## Exploitation Techniques

**垂直权限提升（User → Admin）：**
```
# 直接访问管理路径
GET /admin/users
GET /api/admin/settings

# 修改角色参数
POST /api/users/me {"role": "admin"}
PUT /api/users/me {"is_admin": true}

# 利用参数污染
POST /register {"username": "test", "role": "user", "role": "admin"}

# HTTP 头绕过
X-Original-URL: /admin/users
X-Rewrite-URL: /admin/users
```

**API Gateway / 中间件绕过：**
- 路径规范化差异：`/admin/./users`、`/ADMIN/users`、`/admin%2fusers`
- HTTP 方法覆盖：`X-HTTP-Method-Override: PUT`、`_method=DELETE`
- IP 白名单绕过：`X-Forwarded-For: 127.0.0.1`、`X-Real-IP: 127.0.0.1`
- 路径参数注入：`/api/v1/users;admin=true/profile`（Tomcat/Spring）

**RBAC 测试矩阵：**
- 枚举所有角色（admin、manager、user、guest）和所有端点
- 构建 Role × Endpoint 矩阵，用每个角色的凭证测试每个端点
- 关注：高权限端点（CRUD 用户、系统配置）是否对低权限角色返回 403

**水平权限提升（User A → User B）：**
```
# 修改请求中的用户标识
GET /api/users/1001/profile → GET /api/users/1002/profile
POST /api/account {"user_id": "victim_id"}

# 密码重置流程账户切换
POST /api/reset-password {"token": "valid_token", "email": "victim@target.com"}
```
- 通过 OTP 泄露接管他人账户

**多租户隔离绕过：**
- 修改 `tenant_id`/`org_id` 参数访问其他租户数据
- GraphQL 查询中跨租户查询
- 共享资源（文件存储、缓存）中的租户数据泄露

**SSO/SAML 攻击：**
- SAML 签名验证绕过：修改断言中的用户身份但签名仍有效
- XML 签名包装攻击
- OAuth redirect_uri 篡改
- JWT 算法混淆（`alg: none`、RS256 → HS256）

**认证流程利用：**
- 密码重置 token 重用或可预测
- OTP 在 API 响应中泄露
- 验证码绕过（修改响应、速率限制绕过、验证码重用）
- 账户恢复流程中的身份验证缺失

## Detection Checklist

- [ ] 枚举所有 API 端点并测试未认证访问
- [ ] 对每个管理功能用普通用户凭证测试是否可访问
- [ ] 测试角色参数是否可被客户端篡改（注册、更新 profile）
- [ ] 验证多租户隔离（切换 tenant_id 是否可访问其他租户数据）
- [ ] 检查 SAML/OAuth/JWT 实现的安全性（签名验证、算法限制）
- [ ] 测试密码重置流程（token 可预测性、跨账户使用）
- [ ] 检查 OTP/验证码是否在 API 响应中泄露
- [ ] 测试速率限制是否可绕过（更换 IP、修改参数）
- [ ] 检查前端路由中隐藏的管理页面
- [ ] 验证 API 端点的 HTTP 方法限制是否完整

## Impact Assessment

**漏洞利用可达到的效果：**
- 完整账户接管：通过密码重置、OTP 泄露等接管任意账户
- 管理权限获取：普通用户提升为管理员
- 跨租户数据泄露：访问其他组织的敏感数据
- 系统完全控制：利用管理权限修改系统配置、访问所有数据
- 大规模数据泄露：利用未授权端点批量提取用户 PII

**严重度判断：**
- **Critical**：可接管任意账户、SAML 签名绕过登录任意用户、可获取管理权限
- **High**：跨租户数据访问、OTP 泄露导致可接管特定账户
- **Medium**：仅可访问低敏感度的管理信息、需要额外条件链式利用


## Real-World Cases

以下案例来自 HackerOne 公开披露的真实漏洞报告，展示了该类漏洞在实际目标中的表现形式。

### Case 1: Cosmos — Unauthorized coins transfer from locking account(s)

- **严重度**: Critical | **CWE**: Improper Access Control - Generic
- **摘要**: The Cosmos SDK was found to have a vulnerability that allowed unauthorized transfer of funds from locking accounts. The issue was specifically identified in the `periodic-locking-account`, but it was ...
- **报告**: https://hackerone.com/reports/2976481

### Case 2: Enjin — Lack of Tenant Scoping Enables Limited Cross-Tenant Data Querying and Mutation

- **严重度**: Critical | **CWE**: Improper Access Control - Generic
- **摘要**: A vulnerability was demonstrated on the Enjin Platform that allowed for limited cross-tenant data querying and mutation, enabling querying or mutating of someone else's data in certain cases. A full a...
- **报告**: https://hackerone.com/reports/2327238

### Case 3: GitHub — SAML Signature verification bypass allows logging into any user (with specific conditions)

- **严重度**: Critical | **CWE**: Improper Access Control - Generic
- **摘要**: The vulnerability allowed an attacker with direct network access to GitHub Enterprise Server to forge a SAML response and gain unauthorized access to the instance, including site administrator privile...
- **报告**: https://hackerone.com/reports/2579939

### Case 4: GitLab — Account Takeover via Password Reset without user interactions

- **严重度**: Critical | **CWE**: Improper Access Control - Generic
- **摘要**: The report submitted to GitLab described a vulnerability that allowed account takeover via the password reset form. The vulnerability was triggered by modifying the JSON request to include the victim'...
- **报告**: https://hackerone.com/reports/2293343

### Case 5: IBM — Unauthenticated Remote Access to Testing Endpoint

- **严重度**: Critical | **CWE**: Improper Access Control - Generic
- **摘要**: Unauthenticated remote access to a testing endpoint was reported, analyzed and remediated.
- **报告**: https://hackerone.com/reports/2192984

### Case 6: MTN Group — Admin Dashboard Access Leads to Updating Merchant Info

- **严重度**: Critical | **CWE**: Improper Access Control - Generic
- **摘要**: The application had a hidden registration endpoint that allowed an unauthorized user to sign up for an admin portal. This granted the user access to the admin dashboard, where they could view, edit, a...
- **报告**: https://hackerone.com/reports/2801787

### Case 7: MTN Group — Unauthorized access to PII leads to Administrator account Takeover

- **严重度**: Critical | **CWE**: Privilege Escalation
- **摘要**: The vulnerability arises from insufficient restrictions placed on the list of post authors, which could be exploited by remote attackers to obtain sensitive information through wp/v2/users/15 requests...
- **报告**: https://hackerone.com/reports/2450685

### Case 8: MTN Group — OTP code Leaked in API Response 

- **严重度**: Critical | **CWE**: Improper Access Control - Generic
- **摘要**: The application allowed users to sign up for device insurance. When getting a quote, an OTP code was sent to the user's phone number for authentication, but the same OTP code was also returned in the ...
- **报告**: https://hackerone.com/reports/2633888

### Case 9: Mars — unauthorized access and add user and change personal information all users

- **严重度**: Critical | **CWE**: Improper Access Control - Generic
- **摘要**: The report describes a vulnerability in the ██████████ website, where unauthorized access to an API endpoint allowed attackers to add new users and modify personal information of existing users. The v...
- **报告**: https://hackerone.com/reports/2828641

### Case 10: Mars — change part of personal information all users

- **严重度**: Critical | **CWE**: Improper Access Control - Generic
- **摘要**: The report describes a vulnerability in the ██████████ website, where unauthorized access to an API endpoint allowed attackers to add new users and modify personal information of existing users. The v...
- **报告**: https://hackerone.com/reports/2828693

