# IDOR Penetration Testing Patterns

当对 Web 应用进行 IDOR 渗透测试时加载此 Skill。覆盖水平越权、API 对象级授权缺失等。

## Attack Surface Discovery

**高风险端点特征：**
- 包含数字 ID 的 API 路径：`/api/users/123`、`/orders/456`
- 查询参数中的对象引用：`?user_id=123`、`?account_id=456`
- GraphQL 查询中的 ID 参数
- 文件下载/导出：`/download?file_id=789`
- 用户间交互功能：消息、订单、报告查看
- 管理功能：用户管理、数据修改接口

**识别信号：**
- 响应中包含顺序递增的 ID（`id: 1001, 1002, 1003`）
- API 文档中暴露的对象关系
- 多步操作中某步缺少所有权验证
- 不同 HTTP 方法对同一资源的授权不一致

## Exploitation Techniques

**基础测试方法：**
1. 创建两个测试账户（Account A 和 Account B）
2. 用 Account A 创建资源，记录资源 ID
3. 用 Account B 尝试访问/修改 Account A 的资源
4. 比较响应：200 OK = IDOR 存在

**参数篡改：**
```
# 替换 ID 值
GET /api/users/1001/profile → GET /api/users/1002/profile

# 批量替换（Burp Intruder）
GET /api/orders/$ID$ → 遍历 1-10000

# 修改请求体中的 ID
POST /api/transfer {"from_account": "mine", "to_account": "mine"} 
→ {"from_account": "victim", "to_account": "mine"}
```

**HTTP 方法切换：**
- GET 被拒绝时尝试 POST、PUT、PATCH、DELETE
- 某些框架对不同方法的授权检查不一致
- `X-HTTP-Method-Override: DELETE` 头绕过方法限制

**GraphQL IDOR：**
```graphql
# 查询其他用户的私密数据
query { user(id: "other-user-id") { email, phone, address } }

# Mutation 修改其他用户数据
mutation { deleteProfileImages(userId: "other-user-id") { success } }
```

**高级技巧：**
- ID 类型混淆：数字 ID → UUID → 用户名 → 邮箱
- 嵌套 IDOR：`/org/123/users/456`（先遍历 org ID 再遍历 user ID）
- 批量操作端点：`/api/bulk-delete` 中混入其他用户的 ID
- 订阅/取消端点：修改 `member_id` 参数接管其他用户的关联
- UUID 预测：检查 UUID v1（包含时间戳和 MAC 地址，可能可预测）vs UUID v4（随机）
- Mass Assignment：`POST /api/users {"name":"test","role":"admin"}` 通过额外字段修改权限

**OWASP API Security 参考：**
- BOLA (Broken Object Level Authorization) = OWASP API Security Top 10 #1
- 关注点：每个 API 端点的每个对象访问都需要授权检查，不仅仅是端点级别

## Detection Checklist

- [ ] 列出所有包含对象 ID 的 API 端点
- [ ] 准备两个不同权限级别的测试账户
- [ ] 对每个端点尝试用 Account B 的凭证访问 Account A 的资源
- [ ] 测试 GET/POST/PUT/PATCH/DELETE 每种方法的授权一致性
- [ ] 检查 GraphQL 查询和 Mutation 中的 ID 参数是否有授权检查
- [ ] 测试批量操作端点是否验证每个 ID 的所有权
- [ ] 检查文件下载/导出端点的对象引用
- [ ] 尝试遍历顺序 ID（如果使用数字 ID）
- [ ] 测试通过修改关联 ID（如 `member_id`、`account_id`）进行账户接管
- [ ] 检查 API 响应中是否泄露了其他用户的敏感信息

## Impact Assessment

**漏洞利用可达到的效果：**
- 数据泄露：访问其他用户的个人信息、订单、消息等
- 数据篡改：修改或删除其他用户的资源
- 账户接管：通过修改关联信息接管其他账户
- 金融损失：取消他人订单、修改价格、转移资金
- 隐私侵犯：大规模遍历获取所有用户数据

**严重度判断：**
- **Critical**：可导致账户接管、可访问/修改敏感财务数据、可批量泄露 PII
- **High**：可读取其他用户的私密数据、可删除其他用户的资源
- **Medium**：仅可访问低敏感度信息、需要额外条件才能利用


## Real-World Cases

以下案例来自 HackerOne 公开披露的真实漏洞报告，展示了该类漏洞在实际目标中的表现形式。

### Case 1: HackerOne — Insecure Direct Object Reference (IDOR) Allows Viewing Private Report Details via /bugs.json Endpoint

- **严重度**: Critical | **CWE**: Insecure Direct Object Reference (IDOR)
- **摘要**: The Insecure Direct Object Reference (IDOR) vulnerability allowed viewing private report details through the /bugs.json endpoint. Any private reports could be accessed by sending a POST request to the...
- **报告**: https://hackerone.com/reports/2487889

### Case 2: HackerOne — Attachment disclosure via summary report 

- **严重度**: Critical | **CWE**: Insecure Direct Object Reference (IDOR)
- **摘要**: A critical vulnerability was discovered in the HackerOne platform that allowed an attacker to gain unauthorized access to attachments belonging to other users through the report summary editing functi...
- **报告**: https://hackerone.com/reports/2442008

### Case 3: IBM — Insecure Direct Object Reference Protection bypass by changing HTTP method in IBM Your Learning endpoint. 

- **严重度**: Critical | **CWE**: Insecure Direct Object Reference (IDOR)
- **摘要**: The Insecure Direct Object Reference vulnerability in the IBM Your Learning endpoint was reported, analyzed, and remediated. The vulnerability allowed bypassing the protection by changing the HTTP met...
- **报告**: https://hackerone.com/reports/2456603

### Case 4: MTN Group — IDOR at mtnmobad.mtnbusiness.com.ng leads to PII leakage. 

- **严重度**: Critical | **CWE**: Insecure Direct Object Reference (IDOR)
- **摘要**: The IDOR vulnerability at mtnmobad.mtnbusiness.com.ng allowed the personal information of users, such as their phone numbers and account details, to be accessed by an attacker who knew the user's emai...
- **报告**: https://hackerone.com/reports/1773609

### Case 5: Mars — █████████ when adding branches to your account

- **严重度**: Critical | **CWE**: Insecure Direct Object Reference (IDOR)
- **摘要**: A vulnerability was identified in the branch addition functionality of the Royal Canin specialized channel website. The issue was classified as an Insecure Direct Object Reference (IDOR) vulnerability...
- **报告**: https://hackerone.com/reports/2756402

### Case 6: Mars — IDOR to account takeover on POST to █████████ by changing member_id parameter

- **严重度**: Critical | **CWE**: Insecure Direct Object Reference (IDOR)
- **摘要**: Website endpoint was vulnerable to account takeover by changing member ID parameter.
- **报告**: https://hackerone.com/reports/2132183

### Case 7: MercadoLibre — Sale cancellations from other sellers without restrictions

- **严重度**: Critical | **CWE**: Insecure Direct Object Reference (IDOR)
- **摘要**: The summary is as follows:

A vulnerability was reported that allowed sale cancellations from other sellers without restrictions. The issue was acknowledged and addressed by MercadoLibre.
- **报告**: https://hackerone.com/reports/2495989

### Case 8: Semrush — IDOR vulnerability reveals additional information

- **严重度**: Critical | **CWE**: Insecure Direct Object Reference (IDOR)
- **摘要**: An issue was identified in the Content Outline Builder product. Changing a user ID in a GraphQL request could reveal additional information about users. A subsequent internal review revealed no eviden...
- **报告**: https://hackerone.com/reports/1770858

### Case 9: lemlist — Authentication Bypass in Subscription Management Endpoint

- **严重度**: Critical | **CWE**: Insecure Direct Object Reference (IDOR)
- **摘要**: A vulnerability was identified in the subscription management functionality that allowed unauthorized access to customer billing information. The issue stemmed from insufficient authentication and aut...
- **报告**: https://hackerone.com/reports/3417162

### Case 10: Autodesk — Insecure Direct Object Reference (IDOR) in GraphQL deleteProfileImages Mutation

- **严重度**: High | **CWE**: Insecure Direct Object Reference (IDOR)
- **摘要**: The Insecure Direct Object Reference (IDOR) vulnerability was discovered in the GraphQL deleteProfileImages mutation of the Autodesk User Profile. The vulnerability could have allowed an attacker to d...
- **报告**: https://hackerone.com/reports/2968039

