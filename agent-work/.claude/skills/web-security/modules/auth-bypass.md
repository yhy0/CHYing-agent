# Authentication Bypass Penetration Testing Patterns

当对 Web 应用进行认证绕过渗透测试时加载此 Skill。覆盖 OTP 绕过、2FA 绕过、默认凭证等。

## Attack Surface Discovery

**高风险功能：**
- 登录表单：用户名/密码认证、SSO 登录
- OTP/2FA 验证：短信验证码、邮箱验证码、TOTP
- 密码重置：邮件重置链接、安全问题
- 账户注册：邀请链接、注册验证
- API 认证：API Key、JWT Token、OAuth Token
- 会话管理：Cookie、Session Token
- 管理面板：默认凭证

**识别信号：**
- OTP/验证码在 API 响应中可见
- 登录尝试无速率限制
- 密码重置 token 在 URL 中且可预测
- 应用使用已知存在默认凭证的组件

## Exploitation Techniques

**OTP/2FA 绕过：**
```
# 1. OTP 在响应中泄露
POST /api/send-otp → Response: {"otp": "123456", "status": "sent"}

# 2. 响应篡改
真实响应: {"verified": false} → 修改为: {"verified": true}

# 3. 空 OTP / 默认值
POST /api/verify-otp {"otp": ""} 
POST /api/verify-otp {"otp": "000000"}

# 4. 暴力破解（无速率限制）
POST /api/verify-otp {"otp": "000001"}
POST /api/verify-otp {"otp": "000002"}
...

# 5. 跳过验证步骤
直接访问 2FA 验证后的页面/API 端点
```

**Token Manipulation：**
> For JWT attacks (alg:none, RS256→HS256, kid injection, jku/x5u injection), see [jwt.md](jwt.md)

```
# Password Reset Token
Analyze token structure, check predictability (timestamp, sequential, weak random)
```

**认证逻辑缺陷：**
- 登录后修改 API 响应中的用户身份信息
- 注册流程中篡改邀请链接参数加入任意工作空间
- 手机号验证流程中绑定非自身的号码
- 密码重置流程中替换目标账户

**默认凭证利用：**
```
admin:admin
admin:password
admin:123456
root:root
test:test
# 特定产品默认凭证
Tomcat: tomcat:tomcat
Jenkins: admin:admin  
Grafana: admin:admin
```

**会话管理攻击：**
- Session Fixation：在登录前设置 session ID
- Cookie 操纵：修改 `is_admin=false` → `is_admin=true`
- Token 重用：注销后的 token 是否仍然有效

**Race Condition 利用：**
- 并发 OTP 验证：同时发送多个 OTP 验证请求，绕过速率限制
- 并发注册：同时注册相同用户名/邮箱，可能创建重复账户或绕过唯一性检查
- 并发密码重置：同时发起多个重置请求，获取多个有效 token

**OAuth 2.0 攻击向量：**
- `state` 参数缺失或固定 → CSRF 攻击窃取授权码
- PKCE bypass：降级到无 PKCE 的 OAuth flow（移除 `code_verifier`）
- `redirect_uri` 篡改：通过开放重定向或子域接管窃取授权码
- Token 泄露：通过 Referer 头或浏览器历史获取 access token

**密码重置 Token 测试方法：**
- 请求多个 reset token，分析结构（是否基于时间戳、用户 ID、可预测 PRNG）
- 测试 token 是否在使用后失效（重用攻击）
- 测试旧 token 在新 token 生成后是否仍有效
- Host header 注入：修改 `Host` 头为攻击者域名，重置链接可能指向攻击者

## Detection Checklist

- [ ] 测试 OTP/验证码是否在 API 响应中泄露
- [ ] 检查 OTP 验证是否有速率限制和锁定机制
- [ ] 尝试空 OTP、默认值（000000）和响应篡改绕过 2FA
- [ ] 测试是否可以跳过 2FA 步骤直接访问认证后的功能
- [ ] 检查 JWT 实现（algorithm confusion、签名验证、payload 篡改）
- [ ] 测试密码重置 token 的可预测性和重用性
- [ ] 扫描管理面板的默认凭证
- [ ] 测试登录尝试的速率限制和账户锁定
- [ ] 检查注销后 session/token 是否立即失效
- [ ] 测试注册/邀请流程中的参数篡改（加入任意组织/工作空间）

## Impact Assessment

**漏洞利用可达到的效果：**
- 任意账户接管：绕过认证登录任意用户账户
- 管理员访问：通过默认凭证或权限提升获取管理权限
- 身份冒充：冒充其他用户执行操作
- 数据泄露：访问被认证保护的敏感数据
- 批量账户接管：自动化利用批量接管用户账户

**严重度判断：**
- **Critical**：可接管任意账户、2FA 完全绕过、管理员默认凭证 + 敏感操作
- **High**：可接管特定账户（需知道目标邮箱/手机号）、OTP 泄露
- **Medium**：需用户交互的认证绕过、仅影响低权限功能


## Real-World Cases

以下案例来自 HackerOne 公开披露的真实漏洞报告，展示了该类漏洞在实际目标中的表现形式。

### Case 1: Drugs.com — Email OTP/2FA Bypass

- **严重度**: Critical | **CWE**: Improper Authentication - Generic
- **摘要**: The application had a 2FA functionality by email OTP. The vulnerability allowed bypassing the 2FA by deleting the "bb_refresh" cookie during the authentication process. This enabled successful login w...
- **报告**: https://hackerone.com/reports/2315420

### Case 2: MTN Group — Ability to Add and Verify Uncontrolled Mobile Numbers Leading to Account Takeover (ATO)

- **严重度**: Critical | **CWE**: Authentication Bypass Using an Alternate Path or Channel
- **摘要**: The vulnerability allowed attackers to manipulate the OTP verification response to bypass the OTP check and link an uncontrolled mobile number to the victim's account. This led to an account takeover ...
- **报告**: https://hackerone.com/reports/2762462

### Case 3: MTN Group — Yet Another OTP code Leaked in the API Response

- **严重度**: Critical | **CWE**: Improper Authentication - Generic
- **摘要**: The OTP code was leaked in the API response, which compromised the purpose of its implementation. The application requested a phone number for authentication and sent an OTP code to the user, but the ...
- **报告**: https://hackerone.com/reports/2635315

### Case 4: MTN Group — Authentication Bypass Leads To  Complete Account TakeveOver on ██████████

- **严重度**: Critical | **CWE**: Authentication Bypass Using an Alternate Path or Channel
- **摘要**: The application's backend logic placed too much trust on the login information submitted by the user, which allowed a remote attacker to bypass authentication and perform account takeover.
- **报告**: https://hackerone.com/reports/1709881

### Case 5: Mars — Critical Unauthenticated Access to Sensitive Employee and Customer Data Including Invoice Details at ████

- **严重度**: Critical | **CWE**: Improper Authentication - Generic
- **摘要**: During a reconnaissance phase, a directory named 'SSO' was discovered on the website ████████. Upon accessing this directory, it redirected to ██████████, where sensitive employee and customer data, i...
- **报告**: https://hackerone.com/reports/2262554

### Case 6: Rocket.Chat — Authentication Bypass in login-token Authentication Method

- **严重度**: Critical | **CWE**: Improper Authentication - Generic
- **摘要**: The Rocket.Chat application contained a vulnerability in the login-token authentication method that allowed for authentication bypass. Improper input data validation in the login-token authentication ...
- **报告**: https://hackerone.com/reports/1447619

### Case 7: Slack — Ability to join an arbitrary workspace by utilizing a proxy to manipulate invite links

- **严重度**: Critical | **CWE**: Improper Authentication - Generic
- **摘要**: A vulnerability was found in Slack that allowed experienced researchers to utilize an intercepting proxy to manipulate invite links and join an arbitrary workspace without admin approval. The issue wa...
- **报告**: https://hackerone.com/reports/1716016

### Case 8: TikTok — Account Takeover via Authentication Bypass in TikTok Account Recovery

- **严重度**: Critical | **CWE**: Authentication Bypass Using an Alternate Path or Channel
- **摘要**: An improper authentication mechanism in TikTok's account recovery process was identified. The vulnerability was reported and has been completely fixed. There was no evidence of exploitation.
- **报告**: https://hackerone.com/reports/2443228

### Case 9: Trellix — default credentials at https://52.42.105.71/

- **严重度**: Critical | **CWE**: Improper Authentication - Generic
- **摘要**: Default credentials were used to gain unauthorized access to a server at the reported IP address. The website was misconfigured, allowing login with default admin account credentials. The password sho...
- **报告**: https://hackerone.com/reports/2160178

### Case 10: U.S. Dept Of Defense — Attacker can Add itself as admin user and can also change privileges of Existing Users [█████████]

- **严重度**: Critical | **CWE**: Improper Authentication - Generic
- **摘要**: The website had a directory that lacked authentication, allowing an attacker to add a new admin user and change the privileges of existing users without any authentication.
- **报告**: https://hackerone.com/reports/2354136

