---
category: cloud
tags: [aws, api_gateway, rest_api, http_api, websocket_api, execute_api, stage, resource, authorizer, api_key, apigateway枚举, 网关]
triggers: [api gateway, execute-api, rest-api-id, apigateway, api endpoint, missing authentication token, api key required, lambda authorizer, cognito authorizer, iam authorizer, api stage, api resource, 网关]
related: [cloud/aws_lambda_enum, cloud/aws_s3_enumeration, cloud/aws_sns_abuse]
---

# AWS API Gateway 枚举与路由分析

## 什么时候用

在前端 JS 或页面中发现了 `execute-api.<region>.amazonaws.com` URL，或者题目涉及 REST API / HTTP API 的鉴权绕过时，应该从 API Gateway 视角展开分析。

API Gateway 在云题里最常见的价值是：
- 作为 Lambda 的**前置入口**：路由 + 鉴权 + 参数转换
- 作为**攻击面暴露点**：错误配置的 authorizer、API key、资源策略
- 从 URL 结构中**反推出 stage / path / 后端函数名**

## 前提条件

- 至少拿到一个 `execute-api` URL、API ID 或 stage 名
- 如果有 AWS 凭证，CLI 枚举能直接拿到完整路由表
- 无凭证时靠 HTTP 探测 + 错误码分析

## 攻击步骤

### 1. 从 URL 拆解结构

API Gateway URL 的标准格式是：

```
https://<rest-api-id>.execute-api.<region>.amazonaws.com/<stage>/<resource>
```

拿到 URL 后第一件事是拆出 `rest-api-id`、`region`、`stage`、`resource`。

### 2. 有凭证时的完整枚举

```bash
# REST API (v1)
aws apigateway get-rest-apis
aws apigateway get-stages --rest-api-id <id>
aws apigateway get-resources --rest-api-id <id>
aws apigateway get-method --http-method GET --rest-api-id <id> --resource-id <rid>
aws apigateway get-authorizers --rest-api-id <id>

# HTTP API (v2)
aws apigatewayv2 get-apis
aws apigatewayv2 get-routes --api-id <id>
aws apigatewayv2 get-stages --api-id <id>
aws apigatewayv2 get-integrations --api-id <id>
aws apigatewayv2 get-authorizers --api-id <id>

# 一次性导出完整 API 定义
aws apigatewayv2 export-api --api-id <id> --output-type YAML \
  --specification OAS30 /tmp/api.yaml

# API Keys
aws apigateway get-api-keys --include-value
```

枚举只需要 `apigateway:GET` 这一个权限。

### 3. 无凭证时的 HTTP 探测

通过不同的 HTTP 方法和路径来推断路由和鉴权类型：

```bash
# 测试路径是否存在
curl -i "https://<id>.execute-api.<region>.amazonaws.com/<stage>/"
curl -i "https://<id>.execute-api.<region>.amazonaws.com/<stage>/test"
```

通过错误码判断：

- **`{"message":"Missing Authentication Token"}`** — 路径存在但需要 IAM 鉴权
- **`{"message":"Forbidden"}`** — 资源策略阻止
- **`{"message":"Unauthorized"}`** — Lambda authorizer 拒绝
- **`{"message":"Internal server error"}`** — 后端函数报错（路径存在）
- **`{"message":"Not Found"}`** — 路径不存在

### 4. 分析鉴权类型并尝试绕过

**IAM Authorizer**：

需要 SigV4 签名：
```bash
curl -X GET "https://<id>.execute-api.<region>.amazonaws.com/<stage>/<resource>" \
  --user <ACCESS_KEY>:<SECRET_KEY> \
  --aws-sigv4 "aws:amz:<region>:execute-api"
```

**Lambda Custom Authorizer**：

从 `Authorization` header 读 token，自行校验：
```bash
curl "https://<id>.execute-api.<region>.amazonaws.com/<stage>/<resource>" \
  -H "Authorization: <token>"
```

有时 authorizer 实现有缺陷（硬编码 token、逻辑绕过、空值通过）。

**API Key**：

```bash
curl -X GET "https://<id>.execute-api.<region>.amazonaws.com/<stage>/<resource>" \
  -H "x-api-key: <key>"
```

如果有 `get-api-keys --include-value` 的权限，可以直接拿到明文 key。

**Cognito Authorizer**：

需要有效的 Cognito token，通常涉及完整的认证流程。

### 5. 从 API Gateway 反推 Lambda

API Gateway 的 integration 会指向后端 Lambda 函数。如果你能枚举 integrations：

```bash
aws apigatewayv2 get-integrations --api-id <id>
```

返回中的 `IntegrationUri` 就是 Lambda ARN，从而可以进一步枚举或调用 Lambda。

## 常见坑

- **stage 不对会直接 404**
  常见的 stage 名：`prod`、`dev`、`staging`、`Prod`、`v1`
- **REST API 和 HTTP API 是两套不同的服务**
  CLI 命令分别是 `apigateway` 和 `apigatewayv2`
- **`Missing Authentication Token` 不代表 token 不对**
  它只是说"我期望 IAM 签名但你没提供"
- **资源策略部署后才生效**
  修改策略后需要重新 deploy stage 才会生效
- **CloudFront 代理的 API Gateway 可能隐藏了真实 URL**
  直接访问 CloudFront URL 和 execute-api URL 可能行为不同

## 变体

- **REST API + Lambda 代理集成**：最常见的组合
- **HTTP API**：更便宜、更简单、默认支持 CORS
- **WebSocket API**：用于实时通信
- **私有 API**：只能从 VPC 内部访问
- **Custom Domain + CloudFront**：真实 execute-api URL 被隐藏

## 相关技术

- [[cloud/aws_lambda_enum]] — API Gateway 通常是 Lambda 的前端入口
- [[cloud/aws_s3_enumeration]] — 前端静态站可能和 API Gateway 同属一个业务
- [[cloud/aws_sns_abuse]] — API Gateway 背后的 Lambda 可能发 SNS 通知
