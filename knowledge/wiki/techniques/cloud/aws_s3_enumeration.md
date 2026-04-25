---
category: cloud
tags: [aws, s3, bucket, object_storage, cloudfront, static_website, listbucket, getobject, bucket_enum, s3枚举, 存储桶]
triggers: [aws s3, amazon s3, s3 bucket, bucket name, bucket enumeration, private bucket name discovery, cloudfront s3 origin, static website, website hosting, s3.amazonaws.com, x-amz, listbucket, getobject, access denied, nosuchbucket, 对象存储, 存储桶]
related: [cloud/aws_lambda_enum, cloud/aws_api_gateway_recon, cloud/aws_sns_abuse]
---

# AWS S3 枚举与 Bucket 线索提取

## 什么时候用

目标站点响应头出现 `Server: AmazonS3`、`x-amz-*`、`CloudFront`，或者页面里泄露了 `s3.amazonaws.com`、对象 URL、OG 图片地址、静态资源路径时，应立即转入 S3 视角分析。

在云题里，S3 往往不只是“静态文件托管”，更常见的价值是：

- 泄露 **bucket 名**
- 暴露 **对象路径**
- 侧面暴露 **账号 ID / 区域 / 业务命名规范**
- 成为 Lambda / CloudTrail / SNS / 网站前端的旁路线索

## 前提条件

- 至少拿到 bucket 名、对象 URL、CloudFront 源站痕迹中的一种
- 最好同时记录返回状态：`200`、`403 AccessDenied`、`404 NoSuchKey`、`404 NoSuchBucket`
- 如果有凭证，CLI 枚举会更快；无凭证时主要靠 HTTP 探测

## 攻击步骤

### 1. 先从现有页面里提取 bucket 名

重点看这些位置：

- `og:image`、`src`、`href`、CSS `url(...)`
- JS 常量、注释、source map
- XML 错误页中的 `<BucketName>` 或主机名
- CloudTrail / 日志路径命名
- 题目附件里的 IAM policy、Lambda 代码、环境变量

常见格式：

- `https://<bucket>.s3.amazonaws.com/<key>`
- `https://s3.amazonaws.com/<bucket>/<key>`
- `https://<bucket>.s3.<region>.amazonaws.com/<key>`
- `http://<bucket>.s3-website-<region>.amazonaws.com/`

### 2. 区分是 REST 端点还是静态网站端点

**REST 端点** 常见于对象直链：

```bash
curl -i "https://<bucket>.s3.amazonaws.com/"
curl -i "https://<bucket>.s3.amazonaws.com/<known-key>"
```

**静态网站端点** 常见于前端托管：

```bash
curl -i "http://<bucket>.s3-website-<region>.amazonaws.com/"
```

这两类端点的权限语义不同，不要把一个端点的 200/403 直接套到另一个端点上。

### 3. 用最小探测判断权限边界

无凭证时最常做的是：

- 根路径 `GET/HEAD`
- 已知对象 `GET/HEAD`
- 同目录的可猜对象名
- 常见文件：`index.html`、`robots.txt`、`manifest.json`、图片 / JS / CSS

常见信号解释：

- **`AccessDenied`**：bucket 或对象大概率存在，但你没有当前动作权限
- **`NoSuchKey`**：bucket 存在，对象不存在
- **`NoSuchBucket`**：bucket 不存在或域名不对
- **CloudFront 200 + S3 403**：说明 CDN 可能能读，源站本身未公开

### 4. 借 S3 痕迹反推账号和其他资产

以下线索很实用：

- **CloudTrail bucket 命名**：`aws-cloudtrail-logs-<accountid>-<random>`
- **对象路径**：`AWSLogs/<account-id>/CloudTrail/<region>/...`
- **业务命名规范**：例如 `wiz-birthday-s3-party` 这类名字可用于找同一前缀的其他资产
- **静态站点 + CloudFront**：往往旁边还有 API Gateway、Lambda、Cognito 等配套服务

### 5. 结合其他服务判断真实影响

最常见的联动方式：

- **S3 -> CloudFront**：前端文件泄露 bucket 名和对象路径
- **Lambda -> S3**：函数从私有 bucket 读模板、配置、附件
- **CloudTrail -> S3**：日志路径泄露账号 ID 和区域
- **SNS / SES -> S3**：通知、邮件、Firehose 等把内容落进 bucket

如果策略里出现 `s3:GetObject`、`s3:PutObject`，要把对象路径和业务逻辑一起看，别只停留在“bucket 存不存在”。

## 常见坑

- **CloudFront 访问成功不等于 bucket 公有**
  CDN 可能有单独的 origin 身份或缓存
- **`403 AccessDenied` 仍然是重要线索**
  它通常已经证明 bucket/对象存在
- **bucket 名是全局唯一的**
  但同名不代表一定属于当前题目，要结合对象路径和页面内容判断
- **REST 端点和 Website 端点不要混用**
  行为、错误码和索引页处理都不同
- **不要只盯根目录**
  很多题只开放已知对象，不开放 `ListBucket`

## 变体

- **预签名 URL**：可短时绕过私有读写限制
- **对象覆盖 / 上传**：若存在 `PutObject`，可能能植入前端资源或投毒模板
- **CloudTrail 日志 bucket**：可反推出账号 ID、区域、时间线
- **私有 bucket 经 Lambda 读出**：S3 自身不可读，但业务函数能代读

## 相关技术

- [[cloud/aws_lambda_enum]] — 很多云题的核心是“借 Lambda 去读私有 S3”
- [[cloud/aws_api_gateway_recon]] — 前端经常通过 API Gateway 间接触发与 S3 交互的 Lambda
- [[cloud/aws_sns_abuse]] — SNS / Firehose 等链路可能把内容落进 S3 或从 S3 拿素材
