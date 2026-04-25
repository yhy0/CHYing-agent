# CTF Knowledge Base — 操作手册

> 给 Claude 的操作手册。每次处理知识库相关任务时先读这个文件。

## 架构

基于 Karpathy "LLM Knowledge Bases" 模式（2026-04-03）：

```
knowledge/                  ← 和 chying_agent/ 同级
├── CLAUDE.md               ← 你正在读的这个文件
├── index.md                ← 全局目录，每页一行 TLDR
├── log.md                  ← 操作日志（只增不减）
│
├── raw/                    ← Layer 1: 原始文档（2861 篇 md），只读
│   ├── ht_binary/
│   ├── ht_web/
│   ├── ghsa/
│   └── ...
│
└── wiki/                   ← Layer 2: LLM 编译的知识
    ├── techniques/         ← 技术 wiki 页面
    │   ├── pwn/            (2 页)
    │   ├── web/            (15 页)
    │   ├── cloud/          (11 页: AWS/GCP/Azure/K8s/容器/CI-CD)
    │   ├── pentest/        (9 页: AD域/Windows提权/Linux提权/数据库)
    │   ├── crypto/         (待编译)
    │   └── misc/           (待编译)
    └── experience/         ← 解题 writeup（等待 ingest 的原料）
```

核心原则：**知识是编译出来的，不是检索出来的。**

---

## 三个操作

### 1. Ingest（编译新知识）

**触发**：用户说"ingest"、"编译"、"更新知识库"等。

**来源**：
- `raw/` 里的原始文档（HackTricks、Awesome-POC、GHSA）
- `wiki/experience/` 里的解题 writeup

**流程**：
1. 读原始素材
2. 和用户讨论关键要点
3. 写/更新 `wiki/techniques/` 下的页面
4. 更新 `index.md`
5. 追加 `log.md`
6. 一篇 writeup 可能影响多个 wiki 页面

**关键**：
- 一次处理一篇或一批同类素材，和用户一起确认
- wiki 页面只**更新**不**堆积**——新认知替换旧段落

### 2. Query（在线搜索）

由 `chying_agent/rag/compiled_kb.py` 的 `CompiledKB.match()` 自动完成。Agent 解题时通过 `kb_search` MCP 工具或自动注入调用。

### 3. Lint（健康检查）

**触发**：用户说"lint"、"检查知识库"等。

**检查项**：
- 断链：`[[xxx]]` 引用了不存在的页面
- 孤立页：没有 inbound link
- 过时：experience/ 里有 writeup 还没 ingest
- 覆盖度：常见 CTF 技术还没有对应页面

---

## 页面格式

### frontmatter 规范

```yaml
---
category: pwn | web | crypto | misc | reverse | forensics | cloud | pentest
tags: [小写标签, 中英双语, 技术关键词]
triggers: [题目中可能出现的关键词或短语]
related: [相关页面的 slug]
---
```

### 正文结构

```markdown
# 技术名称

## 什么时候用
## 前提条件
## 攻击步骤
## 常见坑
## 变体
## 相关技术
```

页面 ID 格式: `{category}/{slug}`，如 `pwn/ret2libc`, `web/sqli`

---

## 产品型历史 CVE 专题约定

当编译对象是某个**具体产品**的历史漏洞专题，而不是通用技术页时，遵循以下约定：

1. **先确认值得单独成页**
   - 同一产品在 `raw/` 或 `experience/` 中已有多篇高质量历史 CVE / PoC 素材
   - 这些素材能抽出稳定的产品指纹、攻击链和验证顺序
   - 如果只是零散一两篇 CVE，优先并入通用技术页的 `tags` / `triggers` / 案例，而不是单独立页

2. **正文必须包含“快速验证顺序”**
   - `指纹与版本线索`
   - `快速验证顺序`
   - `nuclei 优先`
   - `最小化复核请求`
   - `手工 PoC 何时需要`
   - `常见漏扫原因`

3. **对产品型已知漏洞，明确写出 nuclei 优先**
   - 当目标是 `Dify`、`ComfyUI Manager`、`RAGFlow`、`Langflow`、`JumpServer`、`1Panel` 这类**已知产品 + 历史 CVE** 场景时：
   - 先用 `httpx` / 页面标题 / 路径 / 版本线索确认产品
   - 再优先用 `nuclei` 做第一轮验证
   - `nuclei` 命中后再用最小化 `curl` / `requests` 请求复核
   - 只有在模板缺失、命中不稳定或需要深度利用时，才转手工 PoC

4. **不要把 nuclei 优先泛化到技术原语页**
   - 对 `Fastjson`、`Java 反序列化`、`XStream`、`XMLDecoder` 这类**技术原语**，不要机械地写成“先 nuclei”
   - 这类页面应优先强调入口识别、协议特征、解析链和定向验证

5. **仍然坚持“知识是编译出来的，不是 CVE 堆砌”**
   - 产品专题不是时间线，不按年份堆 CVE
   - 重点是把“产品指纹 -> 快速验证 -> 常见利用链 -> 误报/漏报原因”编译成稳定知识

---

## Experience（解题 writeup）

Agent 解完题后自动写 writeup 到 `wiki/experience/`：

```markdown
---
technique: pwn/ret2libc
challenge: EasyPwn
solved: true
date: 2026-04-07
---

# EasyPwn

匹配技术: [[pwn/ret2libc]]
结果: ✅ 成功

## 解题过程
## 关键发现
```

这些 writeup 是**原料**，不参与匹配。用户定期触发 ingest 时，由我提炼进 wiki 页面。

---

## 铁律

1. **原始文档永远不改** — raw/ 和 experience/ 是只读的
2. **wiki 页面只更新不堆积** — 新认知替换旧段落
3. **矛盾不覆盖** — 标注 ⚠️ 矛盾，等人确认
4. **保留所有代码** — 攻击步骤里的代码是最核心的知识
5. **中英双语** — tags 和 triggers 覆盖中英文表达

---

## 扩展编译路线

当前 58 页：
- **PWN** (9): ret2libc, format_string, rop_chain, heap_uaf, one_gadget, ret2csu, stack_pivot, shellcode, canary_bypass
- **WEB** (22): sqli, ssti, deserialization_pickle, java_deserialization, xss, ssrf, xxe, lfi, arbitrary_file_read, file_upload, jwt, auth_bypass, idor, command_injection, race_condition, oauth, nosql_injection, websocket, prototype_pollution, document_report_export, ops_observability_console_attacks, llm_agent_orchestration_attacks
- **CRYPTO** (4): rsa_basic, aes_ecb, hash_extension, padding_oracle
- **CLOUD** (11): aws_lambda_enum, aws_s3_enumeration, aws_sns_abuse, aws_api_gateway_recon, aws_iam_enum, kubernetes_enum, kubernetes_privesc, container_escape, gcp_basics, azure_basics, cicd_attacks
- **PENTEST** (9): ad_enum, ad_kerberos_attacks, ad_delegation_abuse, ad_credential_theft, ad_persistence, ad_certificate_abuse, windows_privesc, linux_privesc, database_attacks
- **FORENSICS** (2): pcap_analysis, memory_forensics
- **MISC** (1): steganography

下一批优先级：
- **PWN**: seccomp_bypass, ret2dlresolve, kernel_exploit
- **CRYPTO**: ecc_attacks, prng_mt19937, lattice_lll, stream_cipher_lfsr
- **WEB（企业系统补充）**: business_logic_workflow, saml_and_sso_attack_surface, api_mass_assignment, parser_logic_bypass
- **FORENSICS**: disk_forensics, windows_forensics, linux_forensics
- **MISC**: encoding_puzzles, pyjail, bashjail
- **PENTEST（补充）**: lateral_movement（psexec/wmi/dcom/winrm）, ad_trusts_forests

---

## 技术细节

- 代码在 `chying_agent/rag/`（compiled_kb.py, client.py）
- `CompiledKB` 加载 `knowledge/wiki/techniques/**/*.md`
- `query_kb()` 为统一查询接口，`query_rag` 是兼容别名
- 内存 ~5MB（vs 旧 RAG ~1.2GB）
- `RAG_ENABLED=false` 全局禁用
