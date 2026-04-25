---
category: forensics
tags: [volatility, memory_dump, memory_forensics, vol3, process_analysis, malware_analysis, registry, windows_forensics, linux_forensics, 内存取证, 内存分析]
triggers: [memory dump, memory forensics, volatility, .dmp, .raw, .vmem, memdump, process memory, crash dump, 内存镜像, 内存分析]
related: [pcap_analysis, steganography]
---

# 内存取证 (Memory Forensics)

## 什么时候用

拿到内存 dump 文件（`.raw`、`.dmp`、`.vmem`、`.lime`），需要从中提取进程信息、网络连接、注册表、文件、凭据或 flag。CTF forensics 中第二常见的题型。

## 前提条件

- **内存 dump 文件**：常见格式 `.raw`、`.dmp`、`.vmem`（VMware）、`.lime`（Linux）
- **Volatility 3 可用**：优先用 vol3，语法更简洁且自动检测 OS profile
- **符号表**：vol3 需要对应 OS 的符号表，从官网下载放到 `volatility3/symbols/`
- ⚠️ VMware 快照需先转换：`vmss2core -W snapshot.vmss snapshot.vmem`

## 攻击步骤

### 1. OS 识别与基本信息

```bash
# Volatility 3 — 自动检测 OS，无需手动选 profile
vol3 -f memory.dmp windows.info.Info
vol3 -f memory.dmp banners.Banners          # Linux 版本

# Volatility 2（旧题）— 需要手动确定 profile
volatility -f memory.dmp imageinfo
volatility -f memory.dmp kdbgscan            # 选进程数最多的 profile
```

### 2. 进程分析：进程树、命令行、环境变量

```bash
vol3 -f memory.dmp windows.pstree.PsTree     # 进程树（找异常父子关系）
vol3 -f memory.dmp windows.pslist.PsList      # 进程列表
vol3 -f memory.dmp windows.psscan.PsScan      # 含隐藏进程（DKOM 绕过）
vol3 -f memory.dmp windows.cmdline.CmdLine    # 命令行参数
vol3 -f memory.dmp windows.envars.Envars      # 环境变量（flag 常藏这里）
```

### 3. 文件提取：扫描与 dump

```bash
vol3 -f memory.dmp windows.filescan.FileScan | grep -i "flag\|secret\|desktop"
vol3 -f memory.dmp windows.dumpfiles.DumpFiles --physaddr 0x3e8ba070
vol3 -f memory.dmp windows.dumpfiles.DumpFiles --pid 3152
vol3 -f memory.dmp windows.mftscan.MftScan | grep -i flag  # 含已删除文件
```

### 4. 网络与注册表

```bash
# 网络连接
vol3 -f memory.dmp windows.netscan.NetScan
vol3 -f memory.dmp windows.netscan.NetScan | grep ESTABLISHED

# 注册表
vol3 -f memory.dmp windows.registry.hivelist.HiveList
vol3 -f memory.dmp windows.registry.printkey.PrintKey \
  --key "Software\Microsoft\Windows\CurrentVersion\Run"

# 密码哈希
vol3 -f memory.dmp windows.hashdump.Hashdump
vol3 -f memory.dmp windows.lsadump.Lsadump
```

### 5. 恶意软件检测与 YARA 搜索

```bash
vol3 -f memory.dmp windows.malfind.Malfind --dump  # RWX 内存区域
vol3 -f memory.dmp windows.ssdt.SSDT                # SSDT hook
vol3 -f memory.dmp windows.vadyarascan.VadYaraScan --yara-rules "flag{"
vol3 -f memory.dmp yarascan.YaraScan --yara-rules "CTF{"
```

### 6. Linux 内存分析

```bash
vol3 -f memory.dmp linux.bash.Bash                     # Bash 历史
vol3 -f memory.dmp linux.psaux.PsAux                   # 进程列表
vol3 -f memory.dmp linux.check_syscall.Check_syscall    # syscall hook
vol3 -f memory.dmp linux.check_modules.Check_modules    # 模块检查
```

### 7. 字符串搜索与进程内存 dump

```bash
# 全局搜索 + 关联进程
strings memory.dmp > /tmp/strings.txt
vol3 -f memory.dmp windows.strings.Strings --strings-file /tmp/strings.txt

# dump 进程完整地址空间（含堆栈，找 flag 用这个）
# vol2: volatility -f memory.dmp --profile=PROFILE memdump -p 2168 -D /tmp/
strings /tmp/2168.dmp | grep -i "flag\|CTF{"

# 精确搜索
vol3 -f memory.dmp windows.vadyarascan.VadYaraScan --yara-rules "flag{" --pid 2168
```

### CTF 常见模式速查

| 模式 | 提取方法 |
|------|----------|
| flag 在进程内存 | `vadyarascan --yara-rules "flag{"` 或 memdump + strings |
| flag 在环境变量 | `windows.envars.Envars` |
| 加密文件密钥在内存 | dump 加密进程 → 搜索密钥特征 |
| flag 在注册表 | `printkey` 遍历可疑路径 |
| 删除文件恢复 | `filescan` + `dumpfiles` |
| 勒索密钥恢复 | MFT mtime → PRNG seed → 推导密钥 |
| PowerShell 脚本 | dump powershell.exe → 提取脚本块 |

## 常见坑

- **Vol2 vs Vol3 语法差异**：vol3 插件名是 `windows.pslist.PsList`（带命名空间），vol2 是 `pslist`。vol3 自动检测 profile，vol2 需要 `--profile=`。
- **符号表缺失**：vol3 报 "Unsatisfied requirement" → 去 `downloads.volatilityfoundation.org/volatility3/symbols/` 下载 zip。
- **VMware 快照不是内存 dump**：`.vmss` + `.vmem` 需要 `vmss2core` 转换，`.vmem` 单独也能分析但可能缺元数据。
- **procdump vs memdump**：`procdump` 只 dump 可执行代码，`memdump` dump 完整地址空间（含堆栈）。找 flag 用 memdump。
- **psscan 误报**：扫描型插件可能找到已终止进程的残留结构体，注意验证时间戳和 PID 合理性。
- **大 dump 很慢**：4GB+ 优先用 `pslist` + `cmdline` + `netscan` 快速定位，再对特定 PID 深度分析。

## 变体

### KAPE 分级分析
KAPE 导出文件系统工件（非完整内存）：PowerShell 历史 `ConsoleHost_history.txt`（最快出结果）→ Amcache → MFT（小文件 resident data）→ SAM/SYSTEM 哈希。

### 进程内 TLS 密钥提取
从内存中提取 TLS master key 解密 PCAP：在 PCAP 找 Session ID → 在 dump 搜索该字节序列 → OpenSSL `ssl_session_st` 中 `master_key[48]` 紧邻 `session_id[32]` 之前 → 生成 keylog 文件导入 Wireshark。

### Docker 容器取证
`docker save` 导出分层 tar，删除的文件在早期层仍存在。`docker history --no-trunc` 可能泄露构建时传入的密码。

## 相关技术

- [[pcap_analysis]] — 内存中提取的 TLS 密钥可用于解密网络流量
- [[steganography]] — 从内存中 dump 出的文件可能包含隐写数据
