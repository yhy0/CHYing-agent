---
category: web
tags: [idor, bola, broken object level authorization, insecure direct object reference, broken access control, 水平越权, 垂直越权, 对象级授权, 对象引用, 业务对象, 多租户越权]
triggers: [idor, bola, broken access control, object authorization, object level authorization, access control, user_id, uid, id=, order_id, invoice_id, file_id, doc_id, attachment_id, taskId, processInstanceId, tenant_id, employee_id, dept_id, profile, attachment, export, download, workflow, ticket, 通讯录, 审批, 工单, 订单, 附件, 导出, 越权, 水平越权, 垂直越权]
related: [web/auth_bypass, web/jwt, web/oauth, web/file_upload, web/lfi]
---

# IDOR / BOLA（对象级越权）

## 什么时候用

- 接口中直接出现对象标识符，如 `id`、`user_id`、`order_id`、`file_id`、`doc_id`
- 路径、查询参数、JSON Body、Header、Cookie 中存在可替换的业务对象引用
- 低权限用户已登录，但可以访问详情、下载、导出、修改、审批、删除等对象操作
- 企业系统出现这些业务语义时要特别警惕：`通讯录`、`审批流`、`工单`、`合同`、`订单`、`附件`、`报表导出`
- 多租户系统中存在 `tenant_id`、`org_id`、`dept_id`、`project_id` 这类租户或组织边界参数

## 前提条件

1. 目标暴露了某种可控对象引用，而服务端没有做严格的对象级授权
2. 你至少有一个低权限会话，能观察“正常访问自己的对象”时的请求结构
3. 目标对象 ID 可预测、可枚举，或可从其他接口、页面源码、导出结果、日志中推导出来

## 攻击步骤

### 1. 先找“对象引用”而不是先找漏洞点

优先从这些地方找入口：

- REST 路径：`/api/users/123`、`/api/files/550e8400-e29b-41d4-a716-446655440000`
- 查询参数：`?id=42`、`?docId=10086`
- JSON Body：`{"employee_id": 7, "tenant_id": 2}`
- 隐藏字段或前端状态：`recordId`、`attachmentId`、`processInstanceId`
- 批量接口：`ids=[1,2,3]`、`fileIds=...`

先用自己的对象发一次正常请求，再只改对象标识，不改 Cookie / Token / 其他字段：

```http
GET /api/profile?employee_id=1001 HTTP/1.1
Host: target.local
Cookie: SESSION=low-priv-user
```

把 `employee_id=1001` 改成别人的值：

```http
GET /api/profile?employee_id=1002 HTTP/1.1
Host: target.local
Cookie: SESSION=low-priv-user
```

如果返回了他人数据，或者错误信息明显变化，就要继续深挖。

### 2. 同时测“读、改、删、批量、导出”

很多系统只对详情页做了检查，但忘了对其他动作做校验。常见高价值接口：

- `GET /detail`、`/info`、`/download`
- `POST /export`、`/print`、`/preview`
- `PUT /update`、`PATCH /status`
- `DELETE /remove`
- `POST /batchDelete`、`/batchExport`

示例：

```bash
curl -s "https://target.local/api/document/export?doc_id=1002" \
  -H "Cookie: SESSION=$LOW_PRIV"
```

如果详情接口返回 403，但导出接口能把文件直接打下来，这仍然是 IDOR。

### 3. 注意“多参数组合”与“组织边界”

企业系统常见的不是单个 `id`，而是多维对象定位：

- `tenant_id + user_id`
- `dept_id + employee_id`
- `chat_users[0] + chat_users[1]`
- `workflowId + taskId + attachmentId`

要分别尝试：

1. 只改主对象 ID
2. 只改租户 / 部门 / 项目边界
3. 两个一起改
4. 保留自己的租户边界，只换别人的对象 ID

很多系统只检查“这个租户存在”，却没检查“这个对象是否属于当前租户”。

### 4. 利用错误信息做枚举 Oracle

当接口不直接返回数据时，错误信息常常能泄露对象是否存在：

- `user not found`
- `file does not exist`
- `permission denied`
- `invalid tenant`
- 响应长度、状态码、跳转位置不同

可以先把一个“已知存在但无权访问”的对象和一个“完全不存在”的对象做差分，再批量枚举。

```bash
ffuf -u 'https://target.local/view?username=FUZZ&file=test.doc' \
  -H "Cookie: SESSION=$LOW_PRIV" \
  -w /path/to/names.txt \
  -fr 'User not found'
```

当 `User not found` 被过滤后，剩下的命中往往就是有效用户名，再配合附件名、工单号、合同编号继续横向取数。

### 5. 判断 ID 是否可预测

优先观察这些模式：

- 自增整数：`1001`、`1002`、`1003`
- 短 UUID / 短码：长度固定但熵很低
- 业务编号：`HR-2026-00127`、`PO-2026-8888`
- 前端做了十六进制、Base64、URL 编码，但本质仍然可枚举

编码不等于安全。例如把 `C-285-100` 这类业务编号转成十六进制，本质上还是可预测 bearer token。

### 6. 常见成链方式

IDOR 通常不是终点，而是入口：

- 读取他人资料、手机号、邮箱、身份证
- 下载其他人的附件、备份、导出包、签名文件
- 修改审批状态、收货地址、工单归属、流程处理人
- 读取管理员 Token、重置链接、临时下载链接
- 获取密钥材料后转到 `JWT` 伪造、文件读写、后台接管

## 常见坑

- **只测详情不测导出**：很多漏洞藏在 `export`、`download`、`preview`
- **只改一个参数**：多租户系统经常要联动改 `tenant_id` / `dept_id`
- **忽略批量接口**：批量导出、批量删除往往比单对象接口更松
- **把加密/编码当鉴权**：十六进制、Base64、短签名都可能只是“可枚举的外观”
- **只看状态码**：很多系统对越权对象也返回 200，但正文为空或长度不同

## 变体

- **水平越权**：访问同级用户的数据
- **垂直越权**：普通用户调用管理员动作
- **多租户越权**：跨部门、跨租户、跨项目访问对象
- **附件型 IDOR**：已知 `file_id` 即可下载他人文档
- **流程型 IDOR**：通过 `taskId`、`processInstanceId` 操作他人的审批流

## 相关技术

- [[web/auth_bypass]] — 如果连登录都能绕过，IDOR 会直接扩大成全局后台接管
- [[web/jwt]] — 通过 IDOR 读到密钥、用户 hash 或管理员 token 后可继续伪造身份
- [[web/oauth]] — 业务对象引用有时会出现在授权绑定、回调绑定或账户关联流程中
- [[web/file_upload]] — 通过越权把恶意文件写到他人空间或共享目录
- [[web/lfi]] — 通过越权下载配置、附件或导出包后，再接文件读取链
