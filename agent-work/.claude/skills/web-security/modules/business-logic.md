# Business Logic & DoS Penetration Testing Patterns

当对 Web 应用进行业务逻辑和拒绝服务渗透测试时加载此 Skill。覆盖逻辑缺陷、竞态条件、资源耗尽等。

## Attack Surface Discovery

**业务逻辑高风险区域：**
- 支付/交易流程：价格篡改、折扣叠加、负数数量
- 优惠券/积分系统：重复使用、跨账户转移
- 注册/邀请流程：绕过限制条件、跳过验证步骤
- 权限工作流：审批流程绕过、多步操作中跳步
- 文件上传/导出：绕过类型检查、大小限制

**DoS 攻击面：**
- 正则表达式处理：ReDoS（正则回溯导致 CPU 耗尽）
- HTTP/2 实现：CONTINUATION flood、stream reset
- 大 payload 处理：Markdown 渲染、JSON/XML 解析
- 定时任务：wp-cron.php、scheduled jobs
- 数据库查询：构造导致全表扫描的查询

**竞态条件目标：**
- 余额扣减/积分消耗操作
- 优惠券/兑换码使用
- 文件上传后的处理流程
- 限次操作（投票、点赞、领取）

## Exploitation Techniques

**业务逻辑绕过：**
```
# 价格篡改
POST /api/checkout {"item_id": 123, "price": 0.01}  # 修改前端传递的价格

# 负数量
POST /api/cart {"item_id": 123, "quantity": -1}  # 负数量可能导致退款

# 工作流跳步
# Step 1: 填写信息 → Step 2: 验证 → Step 3: 确认
# 直接请求 Step 3 的 API，跳过 Step 2 验证

# 参数污染
POST /api/apply-coupon {"coupon": "SAVE50", "coupon": "SAVE50"}  # 双重应用
```

**竞态条件利用：**
```python
# 并发请求（使用相同优惠券）
import asyncio, aiohttp

async def redeem(session, url, coupon):
    return await session.post(url, json={"coupon": coupon})

async def race():
    async with aiohttp.ClientSession() as session:
        tasks = [redeem(session, url, "COUPON123") for _ in range(50)]
        results = await asyncio.gather(*tasks)
        success = sum(1 for r in results if r.status == 200)
        print(f"Redeemed {success} times")  # 应该只成功1次
```
- 使用 Turbo Intruder（Burp 扩展）发送并发请求
- 关注：余额扣减、限次操作、唯一性约束

**ReDoS（正则表达式拒绝服务）：**
```
# 典型易受攻击的正则
(a+)+b     → 输入: "aaaaaaaaaaaaaaaaaa!"
(a|a)+b    → 指数级回溯
([a-zA-Z]+)*@  → 邮箱验证

# 测试方法：发送使正则回溯的长输入
aaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

**HTTP/2 DoS：**
- CONTINUATION flood：发送大量 CONTINUATION 帧耗尽内存
- Stream reset flood：快速创建并重置 stream
- HPACK bomb：构造压缩后很小但解压后极大的头部

**应用层 DoS：**
- 大 Markdown payload：嵌套列表/引用导致渲染超时
- XML bomb（Billion Laughs）：指数级实体展开
- GraphQL 深度查询：`{ user { friends { friends { friends { ... } } } } }`
- 慢速攻击：Slowloris、R-U-Dead-Yet

## Detection Checklist

- [ ] 测试支付/交易流程中价格和数量是否可在客户端篡改
- [ ] 测试优惠券/兑换码是否可重复使用（并发竞态）
- [ ] 测试多步工作流是否可跳步执行
- [ ] 使用 Turbo Intruder 测试关键操作的竞态条件
- [ ] 测试 ReDoS：在正则处理的输入点发送回溯 payload
- [ ] 测试大 payload 处理（超大 Markdown、深度嵌套 JSON/XML）
- [ ] 检查 GraphQL 查询深度和复杂度限制
- [ ] 测试速率限制是否可绕过（更换 IP、修改参数大小写）
- [ ] 检查资源限制：文件上传大小、请求超时、并发连接数
- [ ] 验证业务规则在服务端是否有强制执行（不仅仅前端校验）

## Impact Assessment

**漏洞利用可达到的效果：**
- 财务损失：价格篡改、重复兑换、余额操纵
- 服务中断：DoS 导致应用不可用
- 业务规则绕过：跳过审批、绕过限制、获取未授权功能
- 数据完整性破坏：竞态条件导致数据不一致

**严重度判断：**
- **Critical**：直接财务损失、服务完全中断且难以恢复
- **High**：可重复利用的业务逻辑缺陷、持续性 DoS
- **Medium**：需特定条件的 DoS、低影响的逻辑绕过


## Real-World Cases

以下案例来自 HackerOne 公开披露的真实漏洞报告，展示了该类漏洞在实际目标中的表现形式。

### Case 1: U.S. Dept Of Defense —  WordPress application vulnerable to DoS attack via wp-cron.php

- **严重度**: Critical | **CWE**: Uncontrolled Resource Consumption
- **摘要**: The WordPress application was vulnerable to a Denial of Service (DoS) attack via the wp-cron.php script, which could be exploited by sending a large number of requests to the script, causing it to con...
- **报告**: https://hackerone.com/reports/1888723

### Case 2: U.S. Dept Of Defense — DoS at █████(CVE-2018-6389)

- **严重度**: Critical | **CWE**: Uncontrolled Resource Consumption
- **摘要**: A vulnerability in WordPress allowed unauthenticated attackers to launch a denial of service attack by listing a large number of registered .js files from wp-includes/script-loader.php. The vulnerabil...
- **报告**: https://hackerone.com/reports/1887996

### Case 3: Brave Software —  Incorrect security UI of files' download source on brave MacOS

- **严重度**: High | **CWE**: User Interface (UI) Misrepresentation of Critical Information
- **摘要**: The incorrect display of the download source in the Brave download alert was identified. Instead of displaying the actual source of the downloaded file, the browser displayed the referrer header value...
- **报告**: https://hackerone.com/reports/2888770

### Case 4: Cloudflare Public Bug Bounty — Ability to  bypass Admin override on Cloudflare WARP Android

- **严重度**: High | **CWE**: Client-Side Enforcement of Server-Side Security
- **摘要**: A security vulnerability allowed an attacker with local access to an Android device running Cloudflare WARP to bypass the Admin override feature by changing the device's date and time settings. This a...
- **报告**: https://hackerone.com/reports/2043885

### Case 5: Discourse — Application Level DoS - Large Markdown Payload in Reply Section Leading to Resource Exhaustion

- **严重度**: High | **CWE**: Uncontrolled Resource Consumption
- **摘要**: A Denial of Service (DoS) vulnerability was identified in the reply section of the web application. Submitting an excessively large markup payload (approximately 800,000 characters) resulted in the se...
- **报告**: https://hackerone.com/reports/3058919

### Case 6: HackerOne — Any user could upload attachments to pentest scoping form they don't have access to

- **严重度**: High | **CWE**: Business Logic Errors
- **摘要**: The root cause of this issue was insufficient access controls implemented in the attachment upload functionality for pentest scoping forms. The endpoint responsible for handling attachment uploads did...
- **报告**: https://hackerone.com/reports/2450215

### Case 7: Internet Bug Bounty — [CVE-2025-27220] ReDoS in CGI::Util#escapeElement

- **严重度**: High | **CWE**: Uncontrolled Resource Consumption
- **摘要**: The cgi gem contains a vulnerability in the CGI::Util#escapeElement method that is susceptible to Regular Expression Denial of Service (ReDoS). This vulnerability has been assigned the CVE identifier ...
- **报告**: https://hackerone.com/reports/3023605

### Case 8: Internet Bug Bounty — CVE-2024-34750 Apache Tomcat DoS vulnerability in HTTP/2 connector

- **严重度**: High | **CWE**: Uncontrolled Resource Consumption
- **摘要**: CVE-2024-34750: Apache Tomcat Denial of Service Vulnerability

A vulnerability was discovered in Apache Tomcat versions between 11.0.0-M1 and 11.0.0-M20, 10.1.0-M1 and 10.1.24, and 9.0.0-M1 and 9.0.89...
- **报告**: https://hackerone.com/reports/2586226

### Case 9: Internet Bug Bounty — Assertion failed in node::http2::Http2Session::~Http2Session() leads to HTTP/2 server crash

- **严重度**: High | **CWE**: Uncontrolled Resource Consumption
- **摘要**: The Node.js HTTP/2 server was affected by a vulnerability that caused it to crash instantly after receiving a small number of HTTP/2 frames. The issue was caused by a race condition that occurred when...
- **报告**: https://hackerone.com/reports/2453328

### Case 10: Internet Bug Bounty — Denial of Service caused by HTTP/2 CONTINUATION Flood

- **严重度**: High | **CWE**: Uncontrolled Resource Consumption
- **摘要**: A denial of service vulnerability was discovered in Apache Tomcat versions 11.0.0-M1 to 11.0.0-M16, 10.1.0-M1 to 10.1.18, 9.0.0-M1 to 9.0.85, and 8.5.0 to 8.5.98. The vulnerability was caused by the w...
- **报告**: https://hackerone.com/reports/2334401

