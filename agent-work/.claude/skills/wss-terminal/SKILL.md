---
name: wss-terminal
description: Use when extracting WSS terminal connection parameters (URL, cookie, protocol type) from browser pages for wss_connect tool usage
---

# WSS Terminal Probe

当页面包含 Web 终端（xterm.js 等）时，按以下步骤提取 WSS 直连参数。

## 前置条件

- 已通过 `navigate_page` 打开目标页面
- `take_snapshot` 确认页面存在终端元素（`.xterm`、`.terminal`、`Terminal input` 等）

## Step 1: 一键探测脚本

将以下 JS 复制到 `evaluate_script` 中执行：

```javascript
() => {
  const scripts = Array.from(document.querySelectorAll('script:not([src])'));
  let wsScript = null;
  for (const s of scripts) {
    const t = s.textContent;
    if (t.match(/WebSocket|ws:\/\/|wss:\/\/|onData|sendInput/)) {
      wsScript = t;
      break;
    }
  }

  let wsUrl = null;
  if (wsScript) {
    const urlMatch = wsScript.match(/["'\x60](wss?:\/\/[^"'\x60]+)["'\x60]/);
    if (urlMatch) wsUrl = urlMatch[1];
    if (!wsUrl && wsScript.includes('location.host')) {
      const pathMatch = wsScript.match(/["'\x60](\/ws\/[^"'\x60]*)["'\x60]/);
      if (pathMatch) wsUrl = 'wss://' + location.host + pathMatch[1];
    }
  }

  return {
    wsUrl,
    hasSendInput: wsScript?.includes('sendInput') || false,
    hasBinaryPrefix: wsScript?.includes('CLIENT_CMD') || false,
    hasGottyPrefix: wsScript?.match(/['"]1['"].*send/) !== null,
    hasXterm: !!document.querySelector('.xterm'),
    scriptLength: wsScript?.length || 0
  };
}
```

## Step 2: 判断协议类型

根据 Step 1 返回值映射：

| 特征 | 协议 |
|------|------|
| `hasSendInput=true` 或 `hasBinaryPrefix=true` | `ttyd` |
| `hasGottyPrefix=true` | `gotty` |
| URL 包含 `/wetty` | `wetty` |
| URL 包含 `/api/v1/` + `exec` | `k8s` |
| 以上都不匹配 | `generic` |

## Step 3: 提取认证凭证

### 3a. Cookie 提取

1. 先试 JS 可访问的 cookie：`evaluate_script(() => document.cookie)`
2. 如果为空（httpOnly cookie），通过网络请求提取：
   - 调用 `list_network_requests` 获取同域请求列表
   - 选择一个成功的请求（200 状态码），调用 `get_network_request(reqid=<id>)`
   - 从返回的 Request Headers 中提取 `Cookie` 字段值
3. 如果仍为空，检查是否有 `Authorization` header（Bearer token 等），用 `extra_headers` 传递

### 3b. Origin 推断

从目标 URL 提取 Origin（`scheme://host[:port]`）：

```
wss://example.com/ws/shell  →  origin = "https://example.com"
ws://10.0.0.1:8080/ws       →  origin = "http://10.0.0.1:8080"
```

规则：`wss` 对应 `https`，`ws` 对应 `http`。

## Step 4: 连接

```
wss_connect(
  url=<Step1的wsUrl>,
  cookie=<Step3a的cookie>,
  protocol=<Step2的协议>,
  origin=<Step3b的origin>,
  extra_headers=<如有Authorization等额外header>,
  subprotocols=<如服务器要求特定subprotocol，如["tty"]>
)
```

如果返回 4001 UNAUTHORIZED 或类似认证失败：
1. 检查 Cookie 是否完整（httpOnly cookie 是否遗漏）
2. 检查 Origin 是否正确
3. 尝试添加 `subprotocols`（部分 ttyd 服务器要求 `["tty"]`）
4. 如果仍失败，回退到 `window.__wt` 方式（参见 additionalContext 中的初始化脚本）

## 手动分析回退

如果 Step 1 的探测脚本未找到 WebSocket 代码（高度混淆/打包的 JS），则：

1. 用 `evaluate_script` 获取所有 `<script src>` 的 URL
2. 用 `WebFetch` 下载 JS bundle
3. 搜索 `WebSocket`、`ws://`、`wss://` 关键词
4. 从上下文中识别协议格式
