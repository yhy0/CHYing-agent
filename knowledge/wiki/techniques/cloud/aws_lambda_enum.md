---
category: cloud
tags: [aws, lambda, lambda_function, function_url, resource_policy, api_gateway, serverless, principal_star, anonymous_invoke, lambda枚举, 公共调用]
triggers: [aws lambda, lambda function, lambda function url, function url, lambda url, lambda resource policy, lambda invoke, public invocation, anonymous invoke, unauthenticated lambda, principal "*", principal star, api gateway lambda, execute-api, serverless, 公开调用, 资源策略]
related: [cloud/aws_s3_enumeration, cloud/aws_api_gateway_recon, cloud/aws_sns_abuse]
---

# AWS Lambda 枚举与公开调用

## 什么时候用

题目中出现了 `Lambda`、`handler.py`、`function URL`、`execute-api.amazonaws.com`、`lambda resource policy`、`Principal: "*"`、`serverless` 等线索时，就应该先把“函数是谁、从哪里可以打到、谁能调用”这三件事拆开分析。

这类题最常见的误区是把“资源策略允许调用”误读成“匿名用户已经能直接调函数”。真正决定能不能打到函数的，通常是 **Function URL**、**API Gateway 路由**、**事件源** 或 **已获取的 AWS 凭证**。

## 前提条件

- 至少拿到一个线索：函数名、函数 URL、API Gateway URL、策略文件、源码压缩包、CloudFormation/Terraform 配置、日志片段
- 知道大致区域（`us-east-1` 之类）会极大降低枚举难度
- 如果想走 AWS API 原生 `InvokeFunction`，通常还需要函数名/ARN 和有效 AWS 凭证

## 攻击步骤

### 1. 先确认“调用面”而不是只盯着策略

常见入口有 4 类：

- **Function URL**：形如 `https://<id>.lambda-url.<region>.on.aws/`
- **API Gateway**：形如 `https://<rest-api-id>.execute-api.<region>.amazonaws.com/<stage>/<path>`
- **事件源**：S3 / SNS / SQS / EventBridge / DynamoDB 流等
- **AWS API 原生调用**：`aws lambda invoke ...`

如果只看到 `Principal: "*"`，那说明“**某个调用面**对任意 principal 开放”，不等于你已经知道调用面本身。

### 2. 从现有素材里反推函数标识

优先从这些位置找：

- **前端 JS / HTML**：是否泄露了 `execute-api` URL、函数 URL、路由名
- **策略文件**：`arn:aws:lambda:<region>:<account-id>:function:<function-name>`
- **源码 / 环境变量**：`API_BASE_URL`、事件字段名、模板路径、S3 bucket 名
- **错误消息 / 日志**：有时会直接回显函数名、API ID、阶段名
- **旁路资产**：CloudTrail bucket、Stack 名、S3 对象路径、源码包文件名

如果题目给的是 API Gateway URL，先把 `rest-api-id`、`region`、`stage`、`path` 全拆出来，不要直接跳到“裸调用 Lambda”。

### 3. 精读资源策略

重点看这几项：

- `Principal`
- `Action`
- `Condition`
- `Resource`

最常见的几种语义：

- `Principal: "*"` + `lambda:InvokeFunction`
  这表示**策略层**允许任意 principal 调用，但你仍然需要一个可到达的调用路径
- `Function URL AuthType = NONE`
  这类才更接近“匿名 HTTP 直接打函数”
- `Condition` 绑定 `AWS:SourceArn`
  常见于只允许某个 API Gateway / EventBridge / SNS topic 触发

### 4. 针对不同调用面做最小验证

**Function URL**：

```bash
curl -i "https://<id>.lambda-url.<region>.on.aws/" \
  -H "Content-Type: application/json" \
  --data '{"test":"ping"}'
```

**API Gateway**：

```bash
curl -i "https://<rest-api-id>.execute-api.<region>.amazonaws.com/<stage>/<path>" \
  -H "Content-Type: application/json" \
  --data '{"key":"value"}'
```

**有凭证时的原生调用**：

```bash
aws lambda invoke \
  --function-name <function-name> \
  --cli-binary-format raw-in-base64-out \
  --payload '{"key":"value"}' /tmp/out.json
cat /tmp/out.json
```

验证时要尽量只改一个变量：路径、方法、Content-Type、JSON 键名、事件字段名。

### 5. 拿到源码或 handler 后，立刻反推事件结构

Lambda 题很容易卡在“函数可调用，但 body 不对”。这时最值钱的是：

- `event["xxx"]` / `event.get("xxx")`
- 路由分支
- 模板 / 文件读取逻辑
- 环境变量（bucket、topic、secret、base URL）

如果 handler 明确从事件读取 `template`、`token`、`name` 等字段，攻击要围绕真实键名做，而不是盲调。

## 常见坑

- **`Principal: "*"` 不等于匿名公网直接可打**
  你可能仍然缺函数 URL、API Gateway 路由，或者缺 AWS 凭证
- **Function URL 和 API Gateway 是两条不同链**
  两者鉴权、事件结构、返回格式都可能不同
- **拿到 API Gateway URL 也不代表知道所有路由**
  错误的 stage / path 常见返回是 `{"message":"Missing Authentication Token"}`
- **别把 CloudFront 误认成 Lambda**
  很多页面是 `CloudFront -> S3`，和 Lambda 没关系
- **同名函数不同版本 / alias 权重**
  某些环境里只有某个 alias 的代码有洞

## 变体

- **Function URL 公开访问**：`AuthType = NONE`
- **API Gateway 代理到 Lambda**：JS 泄露 `execute-api` URL
- **事件驱动 Lambda**：通过 S3 / SNS / SQS 间接触发
- **Layer / Extension 泄露**：配置和依赖不在主函数 zip 内
- **源码包下载**：`get-function` 或预签名链接泄露代码

## 相关技术

- [[cloud/aws_api_gateway_recon]] — 从 `execute-api` URL 反推出真实路由和事件结构
- [[cloud/aws_s3_enumeration]] — 静态站点、bucket 名和对象路径往往能帮你补全 Lambda 线索
- [[cloud/aws_sns_abuse]] — SNS 既可能是通知通道，也可能是 Lambda 的触发器或数据外带链路
