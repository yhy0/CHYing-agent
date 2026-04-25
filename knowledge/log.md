# 操作日志

> 只增不减。每次 ingest / lint / 重要更新追加一条。

## [2026-04-07] ingest | 初始编译

- 创建 vault 结构（CLAUDE.md, index.md, log.md）
- 编译 pwn/ret2libc（源: ht_binary/ 相关文档）
- 编译 pwn/format_string（源: ht_binary/ 相关文档）
- 编译 web/sqli（源: ht_web/ 相关文档）
- 编译 web/ssti（源: ht_web/ 相关文档）
- 编译 web/deserialization_pickle（源: 相关文档）

## [2026-04-09] ingest | Cloud 类别首批编译

- 编译 cloud/aws_lambda_enum（源: raw/ht_cloud/aws-lambda-enum.md, raw/ht_cloud/aws-lambda-function-url-public-exposure.md）
- 编译 cloud/aws_s3_enumeration（源: raw/ht_cloud/aws-s3-athena-and-glacier-enum.md, raw/ht_cloud/aws-cloudfront-enum.md）
- 编译 cloud/aws_sns_abuse（源: raw/ht_cloud/aws-sns-enum.md, raw/ht_cloud/aws-sqs-and-sns-enum.md, raw/ht_cloud/aws-sns-firehose-exfil.md, raw/ht_cloud/aws-sns-data-protection-bypass.md）
- 编译 cloud/aws_api_gateway_recon（源: raw/ht_cloud/aws-api-gateway-enum.md）
- 更新 index.md CLOUD 段
- 同步修复 compiled_kb.py match() 的 category 优先级逻辑（先同类别硬过滤，无命中再回退全库）

## [2026-04-09] ingest | Web 类别批量编译（7 页）

- 编译 web/xss（源: raw/ht_web/dom-xss.md, browext-xss-example.md, chrome-cache-to-xss.md, iframes-in-xss-and-csp.md, xss-in-markdown.md, server-side-xss-dynamic-pdf.md）
- 编译 web/ssrf（源: raw/ht_web/cloud-ssrf--aws.md, cloud-ssrf--gcp-azure-and-others.md, mysql-ssrf.md, url-format-bypass.md）
- 编译 web/xxe（源: raw/ht_web/xxe-xee-xml-external-entity--basic-attacks.md, advanced-vectors-and-tools.md, hidden-surfaces-and-bypasses.md）
- 编译 web/lfi（源: raw/ht_web/lfi2rce-via-*.md 系列 8 篇, via-php_session_upload_progress.md, server-side-inclusion-edge-side-inclusion-injection.md）
- 编译 web/file_upload（源: raw/ht_web/big-binary-files-upload-postgresql.md, phar-deserialization.md, lfi2rce-via-temp-file-uploads.md）
- 编译 web/jwt（源: raw/ht_web/hacking-jwt-json-web-tokens.md）
- 编译 web/command_injection（源: raw/ht_web/command-injection.md）
- 更新 index.md WEB 段

## [2026-04-09] ingest | Cloud 类别补充编译（6 页）

- 编译 cloud/aws_iam_enum（源: raw/ht_cloud/aws-iam-enum.md, aws-sts-enum.md, aws-federation-abuse.md, cognito-*.md 等 6 篇）
- 编译 cloud/kubernetes_enum（源: raw/ht_cloud/kubernetes-basics.md, kubernetes-enumeration.md, kubernetes-role-based-access-control-rbac.md 等 8 篇）
- 编译 cloud/kubernetes_privesc（源: raw/ht_cloud/attacking-kubernetes-from-inside-a-pod.md, pod-escape-privileges.md 等 8 篇）
- 编译 cloud/container_escape（源: raw/ht_linux/docker-*.md, raw/cloud/Docker runC*.md, Containerd*.md 等 12 篇）
- 编译 cloud/gcp_basics（源: raw/ht_cloud/gcp-iam-*.md, gcp-storage-*.md, gcp-cloud-functions-*.md 等 11 篇）
- 编译 cloud/azure_basics（源: raw/ht_cloud/az-azuread--*.md, az-storage*.md, az-function-apps*.md 等 12 篇）
- 更新 index.md CLOUD 段

## [2026-04-09] ingest | Web 文件上传编译

- 编译 web/file_upload（源: raw/ht_web/big-binary-files-upload-postgresql.md, raw/ht_web/via-php_session_upload_progress.md, raw/ht_web/phar-deserialization.md, raw/ht_web/lfi2rce-via-temp-file-uploads.md + 通用知识补充）
- 涵盖 9 个子技术：Content-Type 绕过、扩展名绕过、Webshell、图片马、PHAR 反序列化、Zip Slip、文件名截断、竞争条件、PostgreSQL Large Object 写文件
- 更新 index.md WEB 段

## [2026-04-09] ingest | Web LFI 编译

- 编译 web/lfi（源: raw/ht_web/ 下 10 篇素材：lfi2rce-via-phpinfo.md, lfi2rce-via-php-filters--technique-and-script.md, lfi2rce-via-php-filters--bruteforce-and-advanced.md, lfi2rce-via-nginx-temp-files.md, lfi2rce-via-temp-file-uploads.md, lfi2rce-via-eternal-waiting.md, lfi2rce-via-segmentation-fault.md, lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md, via-php_session_upload_progress.md, server-side-inclusion-edge-side-inclusion-injection.md）
- 涵盖：基本路径穿越、PHP Wrapper（php://filter/input/data）、9 种 LFI→RCE 路线（Filter Chain/phpinfo Race/Session Upload Progress/Nginx Temp/Segfault/Eternal Waiting/compress.zlib/pearcmd/Log Poisoning）、后缀绕过、WAF 绕过、SSI/ESI 注入变体
- 更新 index.md WEB 段

## [2026-04-09] ingest | Pentest 类别批量编译（8 页）

- 编译 pentest/ad_enum（源: raw/ht_ad/bloodhound.md, kerberos-authentication.md, adws-enumeration.md, password-spraying.md 等 8 篇）
- 编译 pentest/ad_kerberos_attacks（源: raw/ht_ad/kerberoast.md, asreproast.md, golden-ticket.md, silver-ticket.md 等 8 篇）
- 编译 pentest/ad_delegation_abuse（源: raw/ht_ad/constrained-delegation.md, unconstrained-delegation.md, resource-based-constrained-delegation.md 等 4 篇）
- 编译 pentest/ad_credential_theft（源: raw/ht_ad/dcsync.md, credentials-mimikatz.md, laps.md, shadow-credentials.md 等 7 篇）
- 编译 pentest/ad_persistence（源: raw/ht_ad/domain-persistence.md, skeleton-key.md, dcshadow.md, custom-ssp.md 等 9 篇）
- 编译 pentest/ad_certificate_abuse（源: raw/ht_ad/ad-certificates.md, certificate-theft.md, domain-escalation--esc*.md 系列 8 篇）
- 编译 pentest/windows_privesc（源: raw/ht_windows/juicypotato.md, roguepotato-and-printspoofer.md, privilege-escalation-abusing-tokens.md 等 12 篇）
- 编译 pentest/linux_privesc（源: raw/ht_linux/euid-ruid-suid.md, linux-capabilities--*.md, escaping-from-limited-bash.md 等 17 篇）
- 更新 index.md 新增 PENTEST 段

## [2026-04-09] ingest | Web 补充编译（5 页）

- 编译 web/race_condition（源: raw/ht_web/race-condition.md, connection-pool-*.md）
- 编译 web/oauth（源: raw/ht_web/oauth-to-account-takeover--core-vulnerabilities.md, oauth-to-account-takeover--advanced-attacks.md）
- 编译 web/nosql_injection（源: raw/ht_web/nosql-injection.md）
- 编译 web/websocket（源: raw/ht_web/websocket-attacks.md, h2c-smuggling.md, http-connection-contamination.md）
- 编译 web/prototype_pollution（源: raw/ht_web/client-side-prototype-pollution.md, prototype-pollution-to-rce.md, express-prototype-pollution-gadgets.md）
- 更新 index.md WEB 段

## [2026-04-09] ingest | CI/CD + 数据库编译（2 页）

- 编译 cloud/cicd_attacks（源: raw/ht_cicd/basic-jenkins-information.md, basic-github-information.md, jenkins-rce-creating-modifying-pipeline.md 等 15 篇）
- 编译 pentest/database_attacks（源: raw/database/Apache CouchDB*.md, H2 Database*.md, raw/ht_network/ 数据库相关多篇）
- 更新 index.md CLOUD 段 + PENTEST 段

## [2026-04-11] ingest | Web 企业系统缺口编译（4 页）

- 编译 web/idor（源: raw/ht_web/idor.md, raw/oa/金和OA C6 OpenFile.aspx 后台越权敏感文件遍历漏洞.md, raw/database/Apache CouchDB 垂直权限绕过漏洞 CVE-2017-12635.md 等）
- 编译 web/auth_bypass（源: raw/middleware/Apache Shiro 认证绕过漏洞 CVE-2020-1957.md, raw/web/JetBrains TeamCity 身份验证绕过漏洞 CVE-2024-27198.md, raw/web/Apache Airflow 默认密钥导致的权限绕过 CVE-2020-17526.md, raw/web/XXL-JOB 默认 accessToken 身份绕过漏洞.md）
- 编译 web/java_deserialization（源: raw/ht_web/basic-java-deserialization-objectinputstream-readobject.md, raw/ht_network/1099-pentesting-java-rmi.md, raw/oa/泛微OA E-cology WorkflowServiceXml RCE--analysis.md 等）
- 编译 web/document_report_export（源: raw/ht_web/pdf-injection.md, raw/oa/帆软报表 V8 任意文件读取漏洞 CNVD-2018-04757.md, raw/oa/致远OA A8 htmlofficeservlet 任意文件上传漏洞.md, raw/oa/泛微OA E-cology WorkflowServiceXml RCE--analysis.md）
- 更新 index.md WEB 段
- 更新 CLAUDE.md 当前页面统计与下一批优先级

## [2026-04-11] ingest | Web 第二批场景扩展（3 页）

- 编译 web/arbitrary_file_read（源: raw/web/金山 V8 终端安全系统 get_file_content.php 任意文件读取漏洞.md, raw/middleware/Apache Solr RemoteStreaming 文件读取与SSRF漏洞.md, raw/web/Nexus Repository Manager 3 未授权目录穿越漏洞 CVE-2024-4956.md, raw/framework/Apache Flink 目录遍历漏洞 CVE-2020-17519.md 等）
- 编译 web/ops_observability_console_attacks（源: raw/web/JumpServer 远程代码执行漏洞 CVE-2024-29201&CVE-2024-29202.md, raw/cloud/Nacos 认证绕过漏洞 CVE-2021-29441.md, raw/ht_network/spring-actuators.md, raw/ht_network/grafana.md, raw/ht_network/5601-pentesting-kibana.md 等）
- 编译 web/llm_agent_orchestration_attacks（源: raw/ai/Langflow code API 未授权远程代码执行漏洞 CVE-2025-3248.md, raw/ai/browser-use WebUI pickle 反序列化漏洞.md, raw/ai/Ollama 未授权访问漏洞 CNVD-2025-04094.md, raw/ht_misc/ai-agent-abuse-local-ai-cli-tools-and-mcp.md, raw/ht_misc/AI-MCP-Servers.md）
- 更新 index.md WEB 段
- 更新 CLAUDE.md 当前页面统计与下一批优先级

## [2026-04-11] ingest | AI 历史 CVE 专题约定补充

- 更新 web/llm_agent_orchestration_attacks：补充 `Dify`、`ComfyUI`、`ComfyUI Manager`、`RAGFlow`、`Flowise` 等产品触发词
- 更新 web/llm_agent_orchestration_attacks：新增“产品型历史 CVE 专题先走 `指纹 -> nuclei -> 复核`”规则
- 更新 CLAUDE.md：新增”产品型历史 CVE 专题约定”，明确产品型已知漏洞优先 `nuclei`，技术原语页不机械套用

## [2026-04-16] ingest | Crypto 类别首批编译（4 页）

- 编译 crypto/rsa_basic（源: skills/cryptography/modules/rsa.md, rsa-attacks.md）
  - 涵盖: 公钥解析、factordb/yafu 分解、小 e 开根、共模攻击、Wiener、Hastad 广播、Coppersmith small_roots、batch GCD、RsaCtfTool 一键工具
- 编译 crypto/aes_ecb（源: skills/cryptography/modules/modern-ciphers.md, modern-ciphers-2.md）
  - 涵盖: ECB 检测、byte-at-a-time 选择明文、cut-and-paste 块拼接、CBC bit-flip、AES-GCM nonce reuse forbidden attack
- 编译 crypto/hash_extension（源: skills/cryptography/modules/modern-ciphers-2.md）
  - 涵盖: Merkle-Damgard 原理、hashpumpy/HashPump/hlextend 三种工具、secret 长度爆破、CRC32 伪造变体、CRIME/BREACH 压缩 oracle
- 编译 crypto/padding_oracle（源: skills/cryptography/modules/modern-ciphers.md, modern-ciphers-2.md）
  - 涵盖: PKCS#7 填充、逐字节解密完整 Python 实现、PadBuster 工具、加密任意明文、Bleichenbacher PKCS#1 v1.5 变体、Manger RSA-OAEP 变体
- 更新 index.md CRYPTO 段（4 条目）
- 当前总计 48 页（PWN 2 + WEB 22 + PENTEST 9 + CLOUD 11 + CRYPTO 4）

## [2026-04-16] ingest | Forensics + Misc 类别首批编译（3 页）

- 编译 forensics/pcap_analysis（源: raw/ht_misc/wireshark-tricks.md, usb-keystrokes.md, dnscat-exfiltration.md, wifi-pcap-analysis.md + skills/forensics-misc/modules/network.md, network-advanced.md）
  - 涵盖: 初始分诊（io,phs/conv,ip）、HTTP 提取（export-objects）、DNS 渗出（hex 拼接/dnscat2）、TLS 解密（keylog/RSA/弱密钥）、USB HID 键盘（8 字节报告解码完整脚本）、WiFi WPA 破解（aircrack-ng/airdecap-ng）、隐蔽通道（TCP flag/ICMP/间隔编码）
- 编译 forensics/memory_forensics（源: raw/ht_misc/volatility-cheatsheet.md + skills/forensics-misc/modules/disk-and-memory.md）
  - 涵盖: vol3 全流程（info→pstree→cmdline→envars→filescan→dumpfiles→netscan→registry→malfind→yarascan）、Linux bash/psaux/syscall、KAPE 分级、TLS 密钥内存提取、Docker 容器取证
- 编译 misc/steganography（源: skills/forensics-misc/modules/steganography.md, stego-image.md, stego-advanced.md + raw/ht_misc/png-tricks.md）
  - 涵盖: 通用分诊流程、PNG（zsteg/CRC 高度修复/调色板隐写）、JPEG（steghide/stegseek/F5 检测）、自定义 LSB（标准+跨通道 PIL 脚本）、音频（频谱/DTMF/LSB/双轨差分）、PDF（6 步排查清单）、变体（FFT/立体图/视频帧累积）
- 更新 index.md 新增 FORENSICS 段 + MISC 段
- 当前总计 51 页（PWN 2 + WEB 22 + PENTEST 9 + CLOUD 11 + CRYPTO 4 + FORENSICS 2 + MISC 1）

## [2026-04-16] ingest | PWN 类别批量编译（7 页）

- 编译 pwn/rop_chain（源: raw/ht_binary/brop*.md, rop-*.md + skills/binary/modules/rop-and-shellcode.md）
  - 涵盖: gadget 查找（ROPgadget/ropper/pwntools）、x86 vs x64 调用约定、ret2syscall execve、写 /bin/sh 到 BSS、libc gadgets
- 编译 pwn/heap_uaf（源: raw/ht_binary/bins-*.md, double-free.md + skills/binary/modules/heap-techniques.md）
  - 涵盖: chunk 结构、bins 分类、unsorted bin libc leak、tcache poisoning（pre/post safe-linking）、fastbin dup、House of Apple 2 FSOP
- 编译 pwn/one_gadget（源: skills/binary/modules/rop-and-shellcode.md, advanced.md）
  - 涵盖: 工具用法、GDB 约束检查、劫持目标（__malloc_hook/__free_hook/GOT/.fini_array）、realloc 调栈技巧
- 编译 pwn/ret2csu（源: raw/ht_binary/ret2csu.md + skills/binary/modules/rop-and-shellcode.md）
  - 涵盖: __libc_csu_init 双 gadget 模式、rdx/rsi/edi 寄存器控制、间接调用 [r12+rbx*8]
- 编译 pwn/stack_pivot（源: skills/binary/modules/rop-advanced.md）
  - 涵盖: leave;ret 机制、迁移到 BSS、xchg rax,rsp、pop rsp、double pivot、off-by-one EBP2Ret
- 编译 pwn/shellcode（源: skills/binary/modules/rop-and-shellcode.md, advanced.md）
  - 涵盖: NX-off 栈执行、ROP→mprotect→shellcode、ORW（open-read-write）、seccomp bypass、字母数字 shellcode、RETF 架构切换
- 编译 pwn/canary_bypass（源: raw/ht_binary/bypassing-canary-and-pie.md, bf-forked-stack-canaries.md）
  - 涵盖: 格式化字符串泄露（%N$p）、overread、fork 逐字节爆破、TLS canary 覆写
- 更新 index.md PWN 段（2→9 条目）
- 更新 CLAUDE.md 页面统计（51→58 页）和下一批编译路线
- 当前总计 58 页（PWN 9 + WEB 22 + PENTEST 9 + CLOUD 11 + CRYPTO 4 + FORENSICS 2 + MISC 1）
