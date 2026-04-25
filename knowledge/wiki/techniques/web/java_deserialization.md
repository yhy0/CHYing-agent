---
category: web
tags: [java deserialization, java serialization, objectinputstream, readObject, ysoserial, gadget chain, java反序列化, 原生反序列化, rmi, jrmp, jmx, xmldecoder, xstream, fastjson]
triggers: [java deserialize, java deserialization, serialized object, objectinputstream, readObject, Serializable, ysoserial, gadget, commonscollections, rmi, jrmp, jmx, xstream, xmldecoder, java blob, viewstate, fastjson, soap xml, 反序列化, java反序列化, 反序列化rce]
related: [web/deserialization_pickle, web/auth_bypass, web/command_injection, web/xxe]
---

# Java 反序列化（含 RMI / XMLDecoder / XStream 等变体）

## 什么时候用

- 目标是 Java Web、中间件、OA、报表、调度、管理控制台或自研 Servlet
- 抓包时看到二进制 Blob、Base64 大字段、`ObjectInputStream`、`Serializable`、`readObject`
- 目标暴露 RMI / JRMP / JMX / Java RPC 端口，如 `1099`、`9010`、`444x`
- SOAP / XML 服务里出现 `XStream`、`XMLDecoder`、`readObject`、`ViewState` 这类高危线索
- 应用支持插件、远程调用、任务调度、文件导入、配置同步、工作流服务

## 前提条件

1. 存在某种会反序列化不可信输入的入口
2. 目标 Classpath 中存在可用 Gadget，或存在会直接执行危险逻辑的业务类
3. 网络链路允许回显、DNS、HTTP 回连或命令执行中的至少一种验证方式

## 攻击步骤

### 1. 先识别入口类型

Java 反序列化不是只有 `ObjectInputStream` 一种形态，常见入口包括：

- **原生序列化流**：`ObjectInputStream.readObject()`
- **RMI / JRMP / JMX**
- **XMLDecoder / XStream**
- **JSF ViewState**
- **Fastjson / Hessian / Dubbo** 等带对象恢复语义的协议

最典型的原生反序列化代码长这样：

```java
ObjectInputStream in = new ObjectInputStream(inputStream);
Object obj = in.readObject();
```

如果某个类在 `readObject()` 里调用了攻击者可控逻辑，就可能直接变成 Gadget Sink。

### 2. 识别输入长什么样

黑盒里常见信号：

- Base64 解码后出现 Java 序列化头
- 某些请求体是长二进制字段，且响应对结构非常敏感
- XML / SOAP 请求里出现可嵌套对象结构
- RMI 服务枚举时提示允许反序列化

RMI 枚举是很好的入口：

```bash
rmg enum 172.17.0.2 1099
rmg guess 172.17.0.2 1099
```

这一步的目标不是马上打 RCE，而是先确定：

- 暴露了哪些 bound name
- 远程对象监听在哪个真实端口
- 是否存在方法猜解空间
- 是否启用了 JEP 290 等过滤

### 3. 先用“无害外带”验证，再切命令执行

不要一上来就反弹 Shell，优先做低噪声验证：

- URLDNS
- DNSlog / HTTP 回连
- `whoami` / `id`
- 读取固定标志文件

RMI 场景下，常见工具链是 `ysoserial`、`marshalsec`、`remote-method-guesser`：

```bash
rmg serial 172.17.0.2 1099 CommonsCollections6 'id' \
  --bound-name plain-server \
  --signature "String execute(String dummy)"
```

如果返回 `ClassNotFoundException`、服务端回连、或外带命中，通常就已经说明反序列化链被触发。

### 4. 注意“业务接口里的非原生变体”

企业系统里很常见的不是裸 `ObjectInputStream`，而是：

- SOAP 接口内部用 `XStream`
- XML 接口走 `XMLDecoder`
- 工作流 / 同步 / 导入接口恢复对象图
- JSF / ViewState / 组件状态恢复

这类请求看起来像普通 XML，但本质仍然是“把不可信数据恢复成对象”。

例如工作流 SOAP 模板：

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <web:doCreateWorkflowRequest>
      <web:string></web:string>
      <web:string>2</web:string>
    </web:doCreateWorkflowRequest>
  </soapenv:Body>
</soapenv:Envelope>
```

如果后端用 `XStream`、`XMLDecoder` 等去反序列化这段内容，就可以尝试从 URLDNS、再到 Gadget 链逐步推进。

### 5. 选链时优先考虑“目标技术栈”

常见线索与优先方向：

- `CommonsCollections`、`Spring`、`Groovy`、`Rome`、`SnakeYAML`
- WebLogic / JBoss / OFBiz / Dubbo / Fastjson
- RMI Registry / DGC / ActivationSystem
- OA、报表、流程引擎里的自定义业务类

选择 Gadget 时要看：

1. 目标库是否真的在 Classpath
2. Java 版本是否支持该链
3. 是否有过滤器、黑名单或 SecurityManager
4. 是否需要特定协议入口，如 RMI / XML / JSON

## 常见坑

- **把所有对象恢复都当成原生序列化**：很多企业系统其实是 `XStream`、`XMLDecoder`、`Fastjson`
- **忽略 JEP 290 过滤**：目标可能会拒绝常见类，但放行了别的业务对象
- **ClassPath 不匹配**：本地生成的 Gadget 不一定适合目标依赖版本
- **只测一个链**：`CommonsCollections` 失败不代表没有其他链
- **只盯着 Web 入口**：RMI / JMX / 调度端口常常更容易利用
- **没有先做外带验证**：直接打命令执行很难区分“链失败”和“无回显”

## 变体

- **原生 Java 序列化**：`ObjectInputStream.readObject()`
- **RMI / JRMP**：网络服务端口上的对象恢复
- **XMLDecoder / XStream**：业务 XML、SOAP、工作流接口
- **组件状态恢复**：如 ViewState
- **客户端反序列化**：服务端返回恶意对象给 Java 客户端

## 相关技术

- [[web/deserialization_pickle]] — Python 侧的等价问题，便于横向类比“反序列化即代码执行语义”
- [[web/auth_bypass]] — 很多 Java 反序列化入口藏在后台、调试、管理、同步接口后面
- [[web/command_injection]] — 反序列化成功后常直接落到命令执行
- [[web/xxe]] — XML 型入口里，XXE 与 XMLDecoder / XStream 经常是相邻面
