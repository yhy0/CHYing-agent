---
category: web
tags: [auth bypass, authentication bypass, unauthenticated access, session forgery, default secret, hardcoded token, route normalization, sso bypass, 未授权访问, 认证绕过, 鉴权绕过, 会话伪造, 默认密钥]
triggers: [auth bypass, authentication bypass, unauthenticated, login bypass, 未授权, 免登录, 认证绕过, 鉴权绕过, session, cookie, secret_key, accessToken, access token, default_token, remember-me, jwt, token, admin, console, ..;, ;.jsp, jsp=/app/rest, backstage, 后台, 管理端, 调度中心, executor]
related: [web/jwt, web/oauth, web/idor, web/java_deserialization, web/command_injection]
---

# 认证绕过 / 未授权访问（Auth Bypass）

## 什么时候用

- 目标存在后台、控制台、调度器、执行器、管理接口，但未登录也能拿到异常丰富的响应
- 同一接口在不同路径写法下返回不同结果，如多斜杠、分号、编码空格、大小写变体
- 应用通过 Cookie、Header、默认密钥、默认令牌、固定 AccessToken 来“信任”客户端
- 企业系统出现 `admin`、`console`、`executor`、`scheduler`、`actuator`、`/app/rest/`、`/manage/` 这类路径时要优先怀疑
- 低权限用户能接触到管理功能，或未授权用户能创建账号、查看系统信息、调用任务执行接口

## 前提条件

1. 目标必须有某种认证边界，比如登录页、Session、Token、SSO、拦截器或路由鉴权
2. 你能控制路径、Header、Cookie、会话内容，或能观察登录前后响应差异
3. 如果利用默认密钥/默认令牌，还需要知道其格式或找到常见默认值

## 攻击步骤

### 1. 先判断“有没有鉴权”，再判断“鉴权在哪里”

不要只看登录页是否存在，要看真正受保护的接口是否被挡住：

- 未登录访问后台页面：返回 `302`、`401`、`403` 还是直接 `200`
- 未登录访问后台 API：是否也被拦截
- 前端路由与后端接口是否共用一套鉴权
- 同一路由不同写法的结果是否一致

推荐先做三组对比：

1. 正常未登录请求
2. 明显受保护路径请求
3. 同一路径的变体请求

### 2. 路由规范化 / 路径解析绕过

很多认证绕过并不是“没有鉴权”，而是“拦截器和业务框架对路径理解不一致”。

典型信号：

- `..;`、`;`、`%2e`、`%2f`
- 双斜杠、尾部点号、编码空格
- 控制器匹配成功，但过滤器没命中

Shiro 这类场景的典型请求：

```http
GET /xxx/..;/admin/ HTTP/1.1
Host: target.local
```

如果 `/admin/` 本来会跳登录页，而 `/xxx/..;/admin/` 直接返回后台内容，就说明存在路径规范化绕过。

类似思路也常出现在：

- `;/` 或 `;.jsp` 后缀污染
- URL 重写和代理层解析不一致
- `%20`、`%09`、`%2e` 触发不同路由

### 3. 默认密钥 / 默认令牌 / 硬编码信任材料

另一类高频问题是“应用做了认证，但默认配置本身就能伪造身份”。

常见位置：

- Flask / Python 应用的 `SECRET_KEY`
- 调度器、执行器之间的 `accessToken`
- remember-me、SSO、签名 Cookie
- 默认管理员密钥、内置 API Token

Airflow 这类场景可以通过默认 `SECRET_KEY` 伪造 Session：

```bash
flask-unsign -u -c '<原始 session>'
flask-unsign -s --secret temporary_key -c "{'user_id': '1', '_fresh': False, '_permanent': True}"
```

如果服务端仍信任这个 Cookie，就能直接伪造成管理员。

XXL-JOB 这类场景则是默认 AccessToken：

```http
POST /run HTTP/1.1
Host: target.local:9999
XXL-JOB-ACCESS-TOKEN: default_token
Content-Type: application/json

{"glueType":"GLUE_PYTHON","glueSource":"import os\nos.system('id')"}
```

这种问题本质上是“认证材料已知”，不是传统口令爆破。

### 4. 未授权 API 直达管理动作

高价值接口通常包括：

- 创建用户
- 分配管理员角色
- 查看系统信息、环境变量、调试接口
- 上传插件、执行任务、热加载脚本
- 下载配置、日志、密钥材料

TeamCity 类似路径经常表现为“前台页面要登录，但 REST API 被特殊路径写法绕过”：

```http
POST /pwned?jsp=/app/rest/users;.jsp HTTP/1.1
Host: target.local:8111
Content-Type: application/json

{
  "username": "ops-admin",
  "password": "ChangeMe123!",
  "roles": { "role": [{ "roleId": "SYSTEM_ADMIN", "scope": "g" }] }
}
```

一旦能创建管理员账号，后续通常就不是“绕过登录”，而是完整后台接管。

### 5. 探测时要做“前后台、页面接口、代理后端”三层拆分

黑盒里最容易漏掉的点是：

- 页面被挡住了，但 API 没被挡住
- 主站被挡住了，子路径的执行器 / 管理端口没挡住
- 反向代理校验了，后端管理服务没校验

因此要分别测：

- 浏览器页面
- REST / RPC / 执行器接口
- 独立端口上的管理服务

## 常见坑

- **把弱口令和认证绕过混为一谈**：默认口令是认证问题，但“默认签名密钥 / 默认 AccessToken”更接近认证绕过
- **只测页面不测 API**：很多洞在 `/app/rest`、`/run`、`/manage`、`/debug`
- **自动跟随 302**：代理工具自动跳登录页时，容易误判真实状态
- **漏看 Header 信任链**：有些接口只信 `X-Access-Token`、`X-Forwarded-*`、内部来源头
- **拿到低权限不继续试**：很多洞虽然只能创建普通账号，但可以再打后台功能、插件、任务执行形成成链

## 变体

- **路径规范化绕过**：过滤器与控制器解析不一致
- **默认密钥会话伪造**：签名 Cookie / remember-me / Session 可伪造
- **默认或硬编码令牌**：调度器、Agent、执行器、节点间通信默认口令
- **未授权管理接口**：管理 API 直接暴露
- **SSO / SAML / OAuth 边界绕过**：登录集成层被错误信任

## 相关技术

- [[web/jwt]] — 令牌伪造属于认证绕过的重要子类，但这里只讲更通用的边界绕过
- [[web/oauth]] — 第三方登录、状态绑定和回调处理错误也会表现为认证绕过
- [[web/idor]] — 绕过登录后，很多系统还会叠加对象级越权
- [[web/java_deserialization]] — 进入后台或调试接口后，常能进一步触发 Java 反序列化
- [[web/command_injection]] — 任务执行器、插件管理、脚本控制台常直接通向命令执行
