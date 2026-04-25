---
category: web
tags: [document, report, export, import, office integration, pdf injection, file preview, attachment, 文档平台, 报表, 导出, 导入, 在线office, 预览, 附件, 模板注入]
triggers: [report, reportserver, WebReport, export, import, upload, download, preview, attachment, office, officeserver, htmlofficeservlet, pdf, pdf_maker, template, workflow, print, form, 报表, 导出, 导入, 预览, 附件, 打印, 协同, 表单, 流程]
related: [web/file_upload, web/lfi, web/ssrf, web/java_deserialization, web/ssti]
---

# 企业文档、报表与导入导出链路攻击面

## 什么时候用

- 目标是文档平台、OA、报表中心、在线 Office、附件系统、协同审批、电子报销、合同管理
- 功能名出现 `导入`、`导出`、`预览`、`打印`、`附件`、`报表设计`、`Office 控件`
- 路径中出现 `report`、`ReportServer`、`WebReport`、`office`、`upload`、`download`、`workflow`
- 业务里会生成 PDF、Excel、Word、报表模板、流程附件、归档包
- 后台存在“为了兼容老系统”保留的打印、Office、批量导入导出接口

## 前提条件

1. 系统提供文档上传、报表读取、附件下载、模板渲染、打印或流程服务能力
2. 某个链路允许用户控制文件名、路径、模板内容、HTML、XML、上传内容或导出参数
3. 攻击结果至少能带来以下之一：文件读取、文件写入、模板执行、后台请求、代码执行

## 攻击步骤

### 1. 先按“业务链路”找接口，不要只按漏洞类型找

优先枚举以下路径和动作：

- `upload` / `download` / `preview`
- `export` / `import` / `print`
- `ReportServer` / `WebReport`
- `office` / `officeserver` / `htmlofficeservlet`
- `attachment` / `template` / `workflow`

这类系统的危险点常常不是首页接口，而是“给业务功能配套的老接口”。

### 2. 报表 / 资源读取链路优先尝试任意文件读取

报表系统经常提供“读取资源文件”“加载模板”“读取地理数据”“导出配置”的能力，如果路径校验薄弱，就会直接读到敏感配置。

典型请求：

```http
GET /WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml HTTP/1.1
Host: target.local
```

高价值目标文件通常包括：

- `privilege.xml`
- 数据库配置
- 平台管理员凭据
- 报表模板目录
- 导出任务缓存目录

这类场景常见链路是：**任意文件读取 -> 拿到后台账号或数据库配置 -> 登录后台 / 横向利用**。

### 3. Office / 附件上传链路优先尝试任意文件写入

在线 Office、历史兼容控件、附件中转接口往往会把客户端提交的内容直接落盘。

典型信号：

- 老旧二进制协议或固定报文头
- 接口无需登录或只做弱校验
- 上传后能直接通过固定路径访问到落地文件

高风险示例路径：

```http
POST /seeyon/htmlofficeservlet HTTP/1.1
Host: target.local
Content-Type: application/octet-stream
```

如果该接口能把 JSP、脚本或任意文件写入 Web 目录，本质上就是“文档链路上的文件上传到 RCE”。

### 4. PDF / 模板 / HTML 生成链路要想到注入

当系统支持：

- 生成 PDF
- 把用户备注、发票说明、表单内容渲染进 PDF
- 导出 HTML 再转 PDF
- 使用富文本或模板引擎生成报告

就要考虑：

- **PDF 注入**
- **模板注入**
- **服务端 SSRF**
- **后台渲染器命令执行**

典型 PDF 注入片段：

```pdf
) /OpenAction << /S /JavaScript /JS (app.alert(1)) >> (
```

如果后端会自动渲染或预览 PDF，这类问题还可能转成 blind SSRF 或后台文件窃取。

### 5. 工作流 / 服务接口是“业务外壳下的技术入口”

很多协同 / 审批系统会暴露 SOAP、XML、Workflow 服务接口，表面看是“流程能力”，本质上却是高危解析入口。

例如：

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

如果服务端把这类 XML 继续交给 `XStream`、`XMLDecoder` 或模板引擎处理，就会落到更底层的技术面：

- XXE
- Java 反序列化
- 模板执行
- 后台命令执行

### 6. 典型成链方式

文档 / 报表 / 导入导出链路常见的完整利用路径：

1. 枚举 `upload` / `ReportServer` / `office` / `workflow` 接口
2. 从文件读取拿配置，或从上传拿写入能力
3. 获取后台凭据、数据库配置、模板目录、附件路径
4. 继续打后台、模板执行、文件上传、反序列化或命令执行

## 常见坑

- **只看主站不看业务子路径**：危险接口常在历史兼容路径里
- **把“附件功能”当普通文件上传**：很多文档系统有自己的存储、预览、转码链
- **忽略 blind 场景**：报表导出、PDF 生成经常是异步任务，没有直接回显
- **忽略模板和资源文件**：读不到源码也可能先读到模板、配置、凭据
- **只测一个文件类型**：Word、Excel、PDF、图片预览链可能共用同一套后台处理器

## 变体

- **报表资源读取**：任意文件读取、配置泄露、管理员密码恢复
- **Office 控件上传**：任意文件写入、WebShell 落地
- **模板 / PDF 注入**：前台输入进入导出文档，触发 JS / SSRF / 渲染链
- **流程服务接口**：以工作流、审批、同步为外壳的高危解析入口
- **附件下载 / 预览**：可控路径、附件 ID、临时文件访问

## 相关技术

- [[web/file_upload]] — 文档与 Office 链路里的上传问题最终常表现为任意文件写入
- [[web/lfi]] — 报表资源读取、附件预览、模板读取经常会走到文件读取
- [[web/ssrf]] — PDF / HTML 渲染器和文档预览服务常能打内网
- [[web/java_deserialization]] — OA / 工作流 XML 服务背后很容易落到 Java 反序列化
- [[web/ssti]] — 报表模板、邮件模板、导出模板如果可控，要同步考虑模板注入
