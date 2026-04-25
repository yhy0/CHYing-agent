---
name: stagnation-recovery
description: Use when stuck, looping on same approach, making no progress after multiple tool calls, or receiving a stagnation warning from the system. Also trigger when you catch yourself retrying the same command with minor variations, getting repeated Permission denied or timeout errors, or unable to advance past a specific step for 10+ tool calls.
---

# Stagnation Recovery - Security Operations

## Core Principle

**停下来比错误方向的加速更有价值。** 当你连续尝试同类操作无果时，问题不是执行力不够，而是方向错了。

## Iron Rules

1. **穷尽验证再放弃**：没有读过报错全文、没有搜索过文档、没有检查过前置条件的，不算尝试过。
2. **先查后问**：你有 wss_exec/docker_exec/WebSearch/Read 等工具，在判定"不可行"之前，必须用工具验证。
3. **换方向不是换参数**：curl 加了 `-k` 还是 403？这不叫换方向。从 client_credentials 换到 device_code flow 才叫换方向。

---

## Step 1: Diagnose - 识别你的卡壳模式

在采取任何行动之前，先判断你属于哪种模式：

| 模式 | 信号 | 根因 |
|------|------|------|
| **A: 原地打转** | 反复执行同一工具、只改参数/flag | 方向错误，需要换攻击面 |
| **B: 环境约束** | Permission denied, 工具缺失, 网络不通 | 硬限制，需要绕道或换工具链 |
| **C: 信息不足** | 盲目尝试、猜测 API 端点/参数 | 缺少侦察，需要回退到信息收集 |
| **D: 攻击链断裂** | 有多个发现但无法串联 | 需要停下来组合攻击链 |
| **E: 工具使用错误** | 命令语法错、参数编码错、curl 格式错 | 需要读文档或用脚本替代手工命令 |

---

## Step 2: Recover - 按模式执行恢复

### Mode A: 原地打转 -> 换攻击面

**强制动作**：
1. 列出你已尝试的所有方向（不是参数变体，是方向）
2. 从下面的攻击树中选择一个**未尝试过**的方向
3. 每个新方向最多尝试 3 次，无果则换下一个

**Web 攻击树**：
```
目标 Web 应用
  ├── 认证绕过: 默认凭据 / SQL注入 / JWT伪造 / OAuth滥用 / Session固定
  ├── 注入攻击: SQLi / XSS / SSTI / SSRF / XXE / Command Injection / LDAP Injection
  ├── 逻辑漏洞: IDOR / 竞态条件 / 业务逻辑绕过 / 价格篡改 / 权限越权
  ├── 文件操作: 上传绕过 / 路径遍历 / LFI/RFI / 反序列化
  ├── 前端攻击: DOM XSS / Prototype Pollution / WebSocket劫持 / PostMessage滥用
  └── 信息泄露: .git泄露 / 备份文件 / 错误页面 / API文档 / 源码泄露
```

**提权攻击树**：
```
初始访问
  ├── Linux: SUID/SGID / sudo滥用 / cron/定时任务 / capabilities / 内核漏洞 / Docker逃逸
  ├── Windows: 服务权限 / 注册表 / AlwaysInstallElevated / Token模拟 / SeImpersonate
  ├── Cloud: IMDS/metadata / IAM提权 / 角色链 / SSRF到云凭据 / 存储桶误配置
  └── K8s: ServiceAccount / RBAC滥用 / etcd / kubelet API / 挂载逃逸
```

**云安全攻击树**：
```
Cloud Target
  ├── Azure: OAuth App滥用 / Managed Identity / device_code flow / Admin Consent攻击
  │         / Dynamic Group注入 / PRT滥用 / Conditional Access绕过
  ├── AWS: IMDS v1/v2 / IAM提权链 / Lambda环境变量 / S3 ACL / STS AssumeRole
  └── GCP: SA密钥 / metadata server / Workload Identity / Org Policy绕过
```

### Mode B: 环境约束 -> 绕道

**强制动作**：
1. 明确列出约束（具体错误信息）
2. 对每个约束检查：是真约束还是可绕过的？
   - Permission denied -> 能否换用户/换路径/换工具？
   - 工具缺失 -> 能否用替代工具？(例: 没有 nmap 用 /dev/tcp 探测)
   - 网络不通 -> 能否通过已有代理/隧道？
3. 确认是硬约束后，**立即放弃这个方向**，不要再尝试任何变体

**常见绕道方案**：
```
约束: 没有编译器         -> 本地编译后传输二进制
约束: 无法出网           -> 利用已有的合法通道（DNS/HTTP回连）
约束: 只读文件系统       -> /tmp, /dev/shm, 内存执行
约束: 没有交互式终端     -> 脚本化、heredoc、base64编码命令
约束: API需要MFA        -> device_code flow, 条件访问策略绕过
约束: reCAPTCHA/验证码  -> API直接调用（绕过前端）、自动化Cookie复用
```

### Mode C: 信息不足 -> 回退侦察

**强制动作**：
1. 停止当前攻击尝试
2. 列出你当前已知的所有信息
3. 识别缺口：你需要知道什么才能推进？
4. 执行针对性侦察

**信息回溯清单**：
```
已发现的凭据:
  [ ] 全部尝试过了吗？在所有可能的服务上？
  [ ] 尝试过密码复用吗？

已发现的端口/服务:
  [ ] 所有端口都枚举过了吗？
  [ ] 每个服务的版本都识别了吗？
  [ ] 有已知漏洞吗？（searchsploit/CVE查询）

已发现的 Web 路径:
  [ ] 做过目录爆破吗？（多个字典）
  [ ] 检查过 robots.txt, .git, backup 文件吗？
  [ ] 每个端点的参数都测过吗？

已发现的用户/账户:
  [ ] 尝试过弱密码/默认密码吗？
  [ ] 做过用户枚举吗？
  [ ] 检查过权限差异吗？
```

### Mode D: 攻击链断裂 -> 组合发现

**强制动作**：
1. 列出所有 key findings（读 progress.md 和 findings.log）
2. 画出当前拥有的信息图：
   ```
   我有: [凭据A] [端口B开放] [漏洞C存在] [配置D泄露]
   我需要: [从B进入] [用A认证] [利用C获取D中的密钥]
   缺失: [A->B的连接方式]
   ```
3. 对每对发现尝试组合：A+B能做什么？B+C呢？A+C呢？
4. 用 record_key_finding(kind='vulnerability', title='Attack Chain Hypothesis: ...', evidence='<key data points>') 记录假设

### Mode E: 工具使用错误 -> 用脚本替代

**强制动作**：
1. 如果 curl 命令反复出错（参数编码、引号嵌套、特殊字符），**立即改用 Python 脚本**
2. 如果多步操作需要中间状态（token获取 -> 使用token），**写成一个完整脚本**
3. 通过 python_poc_exec 或 wss_exec 执行脚本，避免 shell 转义问题

**典型替代**：
```
curl + 复杂参数  -> Python requests 脚本
多步 API 调用    -> Python 脚本（变量传递）
base64编码       -> Python 脚本（避免 shell 转义）
复杂 JSON body   -> Python 脚本（用 dict 构造）
```

---

## Step 3: Execute - 执行新方向

每个新方向必须满足：
- 与之前**本质不同**（不是参数微调）
- 有明确的**验证标准**（怎样算成功，怎样算失败）
- 失败时能产生**新信息**（不是重复已知错误）

执行后立即：
- 成功 -> record_key_finding 记录
- 失败（新信息） -> 更新 progress.md，进入下一个方向
- 失败（无新信息） -> 停止这个方向，回到 Step 1 重新诊断

---

## Anti-Patterns (FORBIDDEN)

| 行为 | 为什么错 | 应该做什么 |
|------|---------|-----------|
| curl 换个 flag 重试 5 次 | 同一方向的参数微调 | 换攻击向量或用 Python 脚本 |
| 反复刷新页面等状态变化 | 被动等待 | 分析为什么状态没变 |
| 连续 take_snapshot 10 次 | 观察不等于行动 | 分析页面内容，决定下一步操作 |
| 猜测 API 端点格式 | 没有侦察就攻击 | 先找到文档/源码/目录列表 |
| 报错后不读报错内容 | 浪费信息 | 逐字读错误信息，提取线索 |
| 有凭据但没在所有服务上试 | 遗漏攻击面 | 系统性地在每个服务上尝试 |
| device_code 过期后重新获取但不改流程 | 不解决根因 | 写脚本一次性完成整个 flow |
