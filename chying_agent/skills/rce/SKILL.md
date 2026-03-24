---
name: rce
description: "识别远程代码执行注入点，生成针对性 payload，验证命令执行并建立反弹 shell。覆盖命令注入、SSTI、反序列化、文件上传等攻击面。当目标存在可控输入参数、模板渲染、反序列化入口或文件上传功能时使用。"
allowed-tools: Bash, Read, Write
---

# 远程代码执行 (RCE)

在目标服务器上执行任意代码或命令，获取系统控制权。

参考文件：
- [PAYLOADS.md](./PAYLOADS.md) — 各类 payload 集合（命令注入、SSTI、反序列化、Webshell、反弹 Shell、绕过技术）
- [TOOLS.md](./TOOLS.md) — 工具使用参考（commix、tplmap、ysoserial）

## 决策流程

```
目标分析
├─ 存在用户可控参数 → 命令注入测试（步骤 1）
├─ 存在模板渲染 → SSTI 测试（步骤 2）
├─ 存在序列化数据 → 反序列化测试（步骤 3）
├─ 存在文件上传 → Webshell 上传（步骤 4）
└─ 以上均无 → 深入侦察，寻找隐藏入口
```

## 工作流程

### 步骤 1：命令注入测试

**检测**

```bash
# 基础测试 — 注入命令分隔符
curl "http://target.com/ping?ip=127.0.0.1;id"
curl "http://target.com/ping?ip=127.0.0.1|id"
curl "http://target.com/ping?ip=127.0.0.1$(id)"

# 时间盲注 — 确认无回显场景
curl "http://target.com/ping?ip=127.0.0.1;sleep 5"
```

**验证检查点**：确认响应中包含命令输出（如 `uid=`）或观察到明确的时间延迟，再进入利用阶段。

**利用**

- 有回显：直接执行系统命令收集信息
- 无回显：使用 DNS/HTTP 外带或时间盲注（参见 [PAYLOADS.md](./PAYLOADS.md) 无回显 RCE 部分）
- 遇到过滤：使用空格绕过、关键字绕过等技术（参见 [PAYLOADS.md](./PAYLOADS.md) 绕过技术部分）
- 自动化检测：使用 commix（参见 [TOOLS.md](./TOOLS.md)）

### 步骤 2：模板注入 (SSTI) 测试

**检测**

```bash
# 数学表达式探测
curl "http://target.com/page?name={{7*7}}"    # Jinja2/Twig
curl "http://target.com/page?name=${7*7}"     # Freemarker
curl "http://target.com/page?name=<%= 7*7 %>" # ERB
```

**验证检查点**：确认响应中出现 `49` 而非原始模板字符串，再继续深入利用。

**利用**

- 确认模板引擎类型后，使用对应 payload 链（参见 [PAYLOADS.md](./PAYLOADS.md) SSTI 部分）
- 自动化检测：使用 tplmap（参见 [TOOLS.md](./TOOLS.md)）

### 步骤 3：反序列化测试

**检测**

- 识别序列化数据格式（Base64 编码的 Java 对象、Python pickle、PHP 序列化字符串）
- 检查 Content-Type 头（如 `application/x-java-serialized-object`）

**验证检查点**：确认目标接受并处理序列化数据（如修改数据后观察不同的错误响应），再发送 RCE payload。

**利用**

- 根据目标语言选择对应的反序列化利用链（参见 [PAYLOADS.md](./PAYLOADS.md) 反序列化部分）
- Java 目标使用 ysoserial（参见 [TOOLS.md](./TOOLS.md)）

### 步骤 4：文件上传 Webshell

**检测**

- 测试上传功能的文件类型限制
- 尝试绕过：双扩展名（shell.php.jpg）、空字节（shell.php%00.jpg）、Content-Type 伪造

**验证检查点**：确认文件已成功上传且可通过 Web 访问（HTTP 200），再执行 Webshell 命令。

**利用**

- 上传对应语言的 Webshell（参见 [PAYLOADS.md](./PAYLOADS.md) 文件上传部分）
- 通过 Webshell 执行命令

### 步骤 5：建立持久访问

**前置检查**：已通过步骤 1-4 中任一方式确认可执行命令。

- 反弹 Shell 获取交互式访问（参见 [PAYLOADS.md](./PAYLOADS.md) 反弹 Shell 部分）
- 提权并持久化

**验证检查点**：确认反弹 Shell 连接成功（收到交互式 prompt），再进行后续操作。
