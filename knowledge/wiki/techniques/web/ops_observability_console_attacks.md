---
category: web
tags: [ops console, observability, monitoring, bastion, jumpserver, service registry, config center, grafana, kibana, prometheus, apm, tracing, actuator, 运维控制台, 可观测性, 监控平台, 堡垒机, 注册中心, 配置中心]
triggers: [grafana, kibana, prometheus, influxdb, opentsdb, superset, jumpserver, bastion, 堡垒机, nacos, consul, eureka, spring actuator, actuator, jolokia, argocd, argo cd, rancher, kubernetes dashboard, 运维平台, 监控大屏, 日志平台, 链路追踪, 注册中心, 配置中心, /metrics, admin console]
related: [web/auth_bypass, web/command_injection, web/prototype_pollution, web/ssrf, cloud/kubernetes_enum, cloud/cicd_attacks, pentest/database_attacks, web/arbitrary_file_read]
---

# 运维与可观测性 Web 控制台攻击面

## 什么时候用

- 目标是运维平台、监控平台、日志平台、堡垒机、注册中心、配置中心、GitOps 控制台
- 指纹中出现 `Grafana`、`Kibana`、`Superset`、`JumpServer`、`Nacos`、`Consul`、`Actuator`
- 页面功能明显偏“平台级管理”：统一监控、日志检索、资产纳管、运维审计、配置下发、作业执行
- 服务暴露了 `admin`、`/metrics`、`/actuator`、`/env`、`/heapdump`、`/jolokia`
- 题目描述里出现 `可观测性`、`监控大屏`、`统一运维`、`堡垒机`、`4A`、`注册配置`

## 前提条件

1. 目标控制台本身具有高权限，能接触集群、资产、凭证、作业、配置或数据源
2. 存在至少一种可利用入口：未授权访问、弱鉴权、默认信任材料、表达式执行、插件、模板、调试接口
3. 你能拿到页面、接口、独立端口或反向代理后的实际控制面

## 攻击步骤

### 1. 先把它当“高价值入口”，不是普通业务站

这类平台的危险点不一定是单个漏洞，而是它们天然掌握：

- 集群节点信息
- 数据源连接串
- 用户与资产关系
- 云与数据库凭证
- 作业编排与执行能力
- 插件、模板、表达式、脚本能力

所以第一步不是急着找注入，而是先判断控制台掌握了什么权力。

### 2. 优先测未授权、默认信任和路径边界

高频入口包括：

- 默认账号或低权限默认账号
- Header 信任
- 默认 JWT / 硬编码密钥
- 匿名访问误开
- 独立端口没挂鉴权

例如配置中心这类问题经常只是“某个 Header 被错误信任”：

```http
GET /nacos/v1/auth/users?pageNo=1&pageSize=9 HTTP/1.1
Host: target.local:8848
User-Agent: Nacos-Server
```

如果返回了用户列表或允许新建用户，本质就是控制台认证边界已经失守。

### 3. 枚举高价值调试与管理接口

对 Spring / Java 类控制台，优先探测：

- `/actuator/health`
- `/actuator/env`
- `/actuator/loggers`
- `/actuator/logfile`
- `/actuator/heapdump`
- `/jolokia`

这些接口常见价值：

- 泄露环境变量、数据库配置、Basic 凭证
- 拉取 Heapdump，直接从内存里挖密钥
- 打开更高日志级别，收集认证流量
- 借 `Jolokia` 或配置变更触发更深的利用链

例如：

```bash
wget http://target.local/actuator/heapdump -O heapdump
strings -a heapdump | grep -nE 'Authorization: Basic|jdbc:|password=|spring.datasource|eureka.client'
```

### 4. 控制台内置“作业/查询/模板/插件”往往是执行入口

很多运维平台为了方便管理，会内置：

- 作业模板
- Playbook / 脚本执行
- 查询语言或表达式
- 仪表盘模板
- 插件上传与安装
- 数据源测试

这些能力一旦边界控制不严，就会从“管理功能”滑到“执行功能”。

JumpServer 就是典型例子：低权限用户如果能创建或修改 Playbook / 模板，就可能在 Celery 容器里执行命令。

```yaml
- name: |
    {{ __import__('os').system('id > /tmp/pwn') }}
```

同理，Grafana、Kibana、Superset、Cacti、OpenTSDB 这类平台也经常因为查询表达式、插件、模板或参数注入落到 RCE。

### 5. 控制台沦陷后的真正价值在“横向”

拿下这类控制台后，优先做的不是继续刷更多洞，而是收集平台掌握的信任材料：

- 数据源账号密码
- 集群 API Token
- SSH / 主机凭证
- 云配置
- 注册中心与服务发现信息
- 内部 URL、服务清单、日志与请求样本

常见横向路径：

- 堡垒机 -> 资产主机
- 监控平台 -> 数据源数据库 / 对象存储
- 注册中心 -> 服务拓扑与内网服务
- Actuator -> 内存密钥 / 配置 / 下游服务
- GitOps / 集群控制台 -> Kubernetes API

## 常见坑

- **把控制台当成普通业务站**：它们泄露的通常不是一条记录，而是整个平台的控制能力
- **只看首页，不看独立端口和后台 API**：很多功能藏在管理端口、执行器、调试端点
- **拿到低权限就停手**：低权限账号也可能能碰模板、作业、资产、日志、凭证
- **忽略平台的“内建能力”**：查询、模板、插件、数据源测试本身就是攻击面
- **忽略后利用价值**：真正值钱的是集群、配置、会话、密钥和横向能力

## 变体

- **可观测平台**：Grafana、Kibana、APM、日志检索、指标看板
- **运维控制台**：堡垒机、资产纳管、作业编排、统一运维
- **注册配置中心**：Nacos、Consul、Eureka、配置下发与服务发现
- **调试控制面**：Actuator、Jolokia、Heapdump、Loggers
- **GitOps / 集群控制台**：Argo CD、Kubernetes Dashboard、Rancher

## 相关技术

- [[web/auth_bypass]] — 很多控制台的第一入口就是未授权、默认信任或会话伪造
- [[web/command_injection]] — 作业、插件、表达式、数据源测试常直接落到命令执行
- [[web/prototype_pollution]] — Kibana 一类控制台常会触发前后端原型链污染到 RCE
- [[web/ssrf]] — 数据源探测、Webhook、渲染、内部请求能力常可打内网
- [[cloud/kubernetes_enum]] — 集群控制台沦陷后通常会转向 Kubernetes 枚举与凭证利用
- [[cloud/cicd_attacks]] — 运维控制台与 CI/CD 控制台在“高权限后台”心智上高度相似
- [[pentest/database_attacks]] — 监控 / BI / 数据平台控制台经常能直接拿到数据库连接能力
- [[web/arbitrary_file_read]] — 日志、配置、导出与调试接口常带来文件和内存产物泄露
