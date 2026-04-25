# 技术知识库索引

> 由 Claude 维护。每次 ingest 操作后更新。

## PWN

- [[pwn/ret2libc]] — 栈溢出 + NX → 返回 libc system("/bin/sh")
- [[pwn/format_string]] — 格式化字符串漏洞：任意读写内存
- [[pwn/rop_chain]] — ROP 链构造（gadget 查找、ret2syscall、x86/x64 调用约定）
- [[pwn/heap_uaf]] — 堆利用（tcache poisoning、fastbin dup、unsorted bin leak、House of 系列）
- [[pwn/one_gadget]] — one_gadget 单地址 shell（约束满足、劫持目标、realloc 调栈）
- [[pwn/ret2csu]] — __libc_csu_init 通用 gadget（控制 rdx/rsi/edi、间接调用）
- [[pwn/stack_pivot]] — 栈迁移（leave;ret、xchg rsp、迁移到 BSS/堆、off-by-one EBP）
- [[pwn/shellcode]] — Shellcode 编写（mprotect ROP→shellcode、ORW seccomp、字母数字 shellcode）
- [[pwn/canary_bypass]] — Canary 绕过（格式化字符串泄露、fork 逐字节爆破、overread、TLS canary）

## WEB

- [[web/sqli]] — SQL 注入（union/blind/error/time-based）
- [[web/ssti]] — 服务端模板注入（Jinja2/Twig/Freemarker/Smarty）
- [[web/deserialization_pickle]] — Python pickle 反序列化 RCE
- [[web/java_deserialization]] — Java 反序列化（ObjectInputStream、RMI/JRMP、XMLDecoder、XStream）
- [[web/xss]] — 跨站脚本（反射/存储/DOM XSS、CSP 绕过、过滤绕过）
- [[web/ssrf]] — 服务端请求伪造（IMDS 利用、gopher、DNS rebinding、云 metadata）
- [[web/xxe]] — XML 外部实体注入（文件读取、OOB 外带、Blind XXE、XXE→SSRF/RCE）
- [[web/lfi]] — 本地文件包含（路径穿越、PHP wrapper、LFI→RCE 多种方式）
- [[web/arbitrary_file_read]] — 任意文件读取（下载/导出/预览/调试接口、协议型读文件、解析层目录穿越）
- [[web/file_upload]] — 文件上传（扩展名绕过、Webshell、图片马、PHAR、竞争条件）
- [[web/jwt]] — JWT 攻击（alg:none、RS256→HS256、弱密钥、JWK/kid 注入）
- [[web/auth_bypass]] — 认证绕过（未授权访问、默认密钥/令牌、路由规范化绕过、会话伪造）
- [[web/idor]] — 对象级越权（水平/垂直越权、多租户边界、附件/导出/流程对象）
- [[web/command_injection]] — 命令注入（分隔符、盲注、空格/关键词绕过、无回显外带）
- [[web/race_condition]] — 竞争条件（TOCTOU、HTTP/2 单包攻击、Turbo Intruder、优惠券重放）
- [[web/oauth]] — OAuth 攻击（授权码劫持、redirect_uri 绕过、state CSRF、token 泄露、账户接管）
- [[web/nosql_injection]] — NoSQL 注入（MongoDB $gt/$ne/$regex、认证绕过、盲注、$where JS 注入）
- [[web/websocket]] — WebSocket 攻击（CSWSH 握手劫持、消息注入、H2C smuggling、认证绕过）
- [[web/prototype_pollution]] — 原型链污染（__proto__/constructor、客户端 PP→XSS、服务端 PP→RCE、Express gadgets）
- [[web/document_report_export]] — 文档、报表与导入导出链路（附件/预览/打印/Office/流程服务）
- [[web/ops_observability_console_attacks]] — 运维与可观测控制台（监控/日志/堡垒/注册配置/调试端点）
- [[web/llm_agent_orchestration_attacks]] — LLM / Agent 编排平台（工作流画布、MCP、工具调用、提示注入、配置投毒）

## PENTEST

- [[pentest/ad_enum]] — 域信息收集（BloodHound、LDAP、SPN、密码喷射、Kerberos 认证）
- [[pentest/ad_kerberos_attacks]] — Kerberos 攻击链（Kerberoast、AS-REP Roast、Golden/Silver/Diamond Ticket、PTT、Overpass-the-Hash）
- [[pentest/ad_delegation_abuse]] — 委派滥用（非约束/约束/RBCD、Printer Bug、S4U2Self/S4U2Proxy）
- [[pentest/ad_credential_theft]] — 凭证窃取（DCSync、Mimikatz、LAPS、Shadow Credentials、NTLM 窃取、DPAPI）
- [[pentest/ad_persistence]] — 域持久化（Golden Ticket、Skeleton Key、DCShadow、自定义 SSP、SID History、AdminSDHolder）
- [[pentest/ad_certificate_abuse]] — ADCS 证书攻击（ESC1-ESC16、Certipy/Certify、证书窃取、PKINIT）
- [[pentest/windows_privesc]] — Windows 本地提权（Potato 系列、Token 滥用、DLL 劫持、服务权限、COM 劫持）
- [[pentest/linux_privesc]] — Linux 本地提权（SUID、Capabilities、Sudo、Cron、Wildcard、NFS、LXD、Path Hijack）
- [[pentest/database_attacks]] — 数据库攻击（MySQL UDF/OUTFILE、PostgreSQL COPY/大对象、Redis 写 Key/Crontab、MSSQL xp_cmdshell）

## CRYPTO

- [[crypto/rsa_basic]] — RSA 基础与常见攻击（小 e 开根、共模、Wiener、Coppersmith、Hastad 广播、batch GCD、RsaCtfTool）
- [[crypto/aes_ecb]] — AES 分组密码攻击（ECB byte-at-a-time、cut-and-paste、CBC bit-flip、GCM nonce reuse）
- [[crypto/hash_extension]] — 哈希长度扩展攻击（MD5/SHA Merkle-Damgard、hashpumpy、CRC32 伪造）
- [[crypto/padding_oracle]] — Padding Oracle 攻击（CBC PKCS#7 逐字节解密、Bleichenbacher RSA、PadBuster）

## CLOUD

- [[cloud/aws_lambda_enum]] — Lambda 枚举与公开调用（资源策略、Function URL、API Gateway 入口）
- [[cloud/aws_s3_enumeration]] — S3 Bucket 线索提取（bucket 名、对象路径、CloudFront 源站）
- [[cloud/aws_sns_abuse]] — SNS 订阅滥用与数据外带（topic policy、Firehose 外带、邮箱限制绕过）
- [[cloud/aws_api_gateway_recon]] — API Gateway 枚举与路由分析（鉴权类型、stage 探测、Lambda 反推）
- [[cloud/aws_iam_enum]] — IAM/STS/Cognito 枚举与提权（凭证利用、AssumeRole、身份池滥用）
- [[cloud/kubernetes_enum]] — Kubernetes 枚举（kubectl、RBAC、ServiceAccount、Secret、Kubelet API）
- [[cloud/kubernetes_privesc]] — Kubernetes 提权（Pod 逃逸、RBAC 滥用、跨 namespace、横向到云）
- [[cloud/container_escape]] — 容器逃逸（Docker privileged、cgroup release_agent、Docker socket、runC CVE）
- [[cloud/gcp_basics]] — GCP 速查（IAM、Storage、Cloud Functions、Compute IMDS、Secret Manager）
- [[cloud/azure_basics]] — Azure 速查（Azure AD、Blob Storage、Function Apps、Key Vault、IMDS）
- [[cloud/cicd_attacks]] — CI/CD 攻击（Jenkins RCE、GitHub Actions Secret、Pipeline 注入、Runner 逃逸）

## FORENSICS

- [[forensics/pcap_analysis]] — 网络流量分析（tshark/Wireshark、HTTP 提取、DNS 渗出、TLS 解密、USB HID、WiFi 破解）
- [[forensics/memory_forensics]] — 内存取证（Volatility 3 全插件链、进程/注册表/文件/网络/恶意软件检测、KAPE 分级）

## MISC

- [[misc/steganography]] — 隐写术（PNG LSB/CRC 修复、JPEG steghide/F5、音频频谱/DTMF、PDF 多层、自定义 LSB 脚本）

## REVERSE

（待编译）
