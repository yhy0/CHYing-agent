---
name: ctf-postmortem
description: 分析 CHYing Agent 的 CTF 比赛日志，统计解题率，诊断失败根因，并输出可操作的系统级优化建议。适用于赛后复盘或定期系统改进。 (project)
---

# CTF 赛后复盘分析

对 CHYing Agent 在一次或多次 CTF 比赛中的表现进行系统性分析，找出失败规律，提出系统级（非题目级）优化建议。

## 数据来源

- **challenge 工作目录**：`agent-work/ctf/<Category>/<challenge_dir>/`
- **关键文件**：
  | 文件 | 内容 |
  |------|------|
  | `progress.md` | 主任务状态、攻击树、Dead Ends、当前阶段 |
  | `findings.log` | 所有 key findings，含 kind/status/evidence |
  | `dumps/commands.log` | 执行命令历史 |
  | `dumps/checkpoints.log` | Reflection 检查点与停滞诊断 |
  | `result.json` | 最终结果（若存在） |

## 执行流程

### 第一步：收集所有 challenge 目录

```
agent-work/ctf/
├── Web/
│   └── <challenge_dir>/
├── PWN/
├── Crypto/
├── Misc/
├── Cloud/
├── reverse/
└── tencent_cloud/
```

用 Glob 工具扫描所有 `*/*/progress.md` 文件，建立题目清单。

对每道题提取：
- **题目名**：从目录名推断
- **类别**：父目录名
- **是否解出**：检查 progress.md 中是否出现 `FLAG{` 或 `flag{` 字样，或 findings.log 中存在 `kind: flag` 条目
- **最终状态**：从 progress.md 的 "Current Phase" 或最后的 Dead Ends 推断

### 第二步：统计解题率

输出如下统计表：

```
## 解题统计

总题数: N
已解出: M (M/N = XX%)
未解出: K

| 类别  | 总数 | 解出 | 解出率 |
|-------|------|------|--------|
| Web   |  X   |  X   |  XX%   |
| PWN   |  X   |  X   |  XX%   |
| Crypto|  X   |  X   |  XX%   |
| Misc  |  X   |  X   |  XX%   |
| Cloud |  X   |  X   |  XX%   |
```

### 第三步：失败题目逐题诊断

对每道未解出的题目，读取其 `progress.md` 和 `findings.log`，提取：

1. **停止原因**（stop_reason）：timeout / consecutive_failures / blocked / max_turns
2. **最后阶段**（Current Phase）：到哪一步卡住了
3. **Dead Ends**：列举所有已证实无效的方向
4. **最后的 highest_anomaly**：最有价值但未被充分利用的线索
5. **工具使用模式**：主要用了哪类工具（executor/browser/reverse/c2）
6. **是否触发了 kb_search**：findings.log 中是否有知识库搜索记录
7. **是否使用了 browser**：是否做过 JS 渲染验证

### 第四步：失败模式归类

将所有失败题目归入以下根因类别（一题可归多类）：

| 根因代码 | 含义 | 识别信号 |
|---------|------|---------|
| `TARGET_UNREACHABLE` | 目标服务不可达 | 大量连接错误/超时，无任何有效响应 |
| `TOOL_GAP` | 缺少合适工具或工具用法错误 | 反复 exec 失败，未尝试 browser/reverse |
| `KB_MISS` | 未搜索知识库，错过已知漏洞/技术 | 存在版本号但无 kb_search，类型为 cloud/misc |
| `JS_BLIND` | JS 渲染内容不可见，curl 看不到真实页面 | Content-Length=0，browser 未启用 |
| `LOOP_SAME_VECTOR` | 在同一攻击向量上反复尝试，未转换方向 | Dead Ends 全属同一类别，攻击树分支单一 |
| `PARTIAL_CHAIN` | 有部分发现但未串联成完整攻击链 | findings.log 有多条 confirmed 但无 exploited |
| `TIMEOUT_TOO_EARLY` | 时间到了但方向是对的，只是执行不够深入 | 最后阶段在正确方向上但 stop_reason=timeout |
| `RECON_SHALLOW` | 侦察不足，缺少关键信息就开始攻击 | progress.md 缺少服务版本/路径/参数信息 |
| `REFLECT_MISSED` | Reflection 机制未触发或触发后未改变策略 | checkpoints.log 无记录，或记录后仍重复死路 |
| `SESSION_REPEAT` | 多次 session 重复相同工具路径 | prior_knowledge 存在但策略未变 |

### 第五步：系统级根因汇总

**重要原则**：所有分析必须是系统级的——不能说"这道题应该用 SSTI"，
只能说"有 N 道题存在版本号但未触发 kb_search，说明触发条件定义不够明确"。

输出格式：

```
## 系统级根因分析

### 最高频根因（按影响题目数排序）

1. **[根因代码]** — 影响 N 道题 (XX%)
   - 证据：<具体题目 + 表现>
   - 系统组件：<哪个模块负责这个行为>
   - 根本原因：<为什么当前系统会导致这个根因>

2. ...

### 次要根因

...
```

### 第六步：优化建议

基于根因分析，按 **P0/P1/P2/P3** 优先级输出系统优化建议：

```
## 优化建议

### P0（立即修复，影响 ≥3 道题）

1. **[建议标题]**
   - 解决根因：[根因代码]
   - 影响范围：N 道失败题目
   - 修改目标：<哪个文件/组件>
   - 具体建议：<系统行为变化，不是解题方法>

### P1（本周修复）

...

### P2（下次比赛前）

...

### P3（长期改进）

...
```

### 第七步：输出完整报告

最终报告结构：

```markdown
# CTF 复盘报告 — <日期/比赛名>

## 1. 解题统计
...

## 2. 失败题目诊断
<每道失败题目一节>

## 3. 系统级根因分析
...

## 4. 优化建议
...

## 5. 执行建议
列出可以立即动手修改的文件和改动方向，
按优先级排序，每项不超过 3 行描述。
```

## 分析原则

### 必须遵守

1. **系统级视角**：所有结论必须能回答"系统哪里有问题"，而非"这道题应该怎么解"
2. **证据驱动**：每个根因必须有具体题目的文件内容作为证据（引用文件路径 + 关键片段）
3. **不针对题目**：禁止输出"题目 X 的解法是..."，只输出"有 N 道题出现了 Y 模式"
4. **可操作性**：每条优化建议必须能落实到具体文件的具体修改，而非泛泛的"要更聪明"

### 根因优先级判断标准

- **P0**：影响 ≥ 3 道题，且有明确可修改的系统组件
- **P1**：影响 2 道题，或影响 1 道但根因特别严重（如目标不可达未快速失败）
- **P2**：影响 1 道题，且修改成本较低
- **P3**：改进类（非修复类），如提升检测精度、增加知识库内容

### 已知系统组件参考

分析时可对照以下组件定位问题归属：

| 组件 | 文件 | 职责 |
|------|------|------|
| PromptCompiler | `chying_agent/prompts/prompt_compiler.md` | 将 recon 数据结构化为 prompt |
| Orchestrator 策略 | `chying_agent/prompts/orchestrator_strategy.md` | 工具选择和委派规则 |
| Executor | `chying_agent/prompts/executor.md` | 执行停止条件和 HTTP 响应处理 |
| Orchestrator 输出 | `chying_agent/prompts/orchestrator_output.md` | 结构化输出格式和必填字段 |
| ReflectionTracker | `chying_agent/claude_sdk/reflection.py` | 停滞检测和软/硬反思触发 |
| ChallengeSolver | `chying_agent/challenge_solver.py` | 主循环、快速失败、recon 流程 |
| Agent Skills | `agent-work/.claude/skills/` | 专项技术知识注入 |

## 快速触发场景

以下情况下触发此 skill：

- 比赛结束后 ("分析一下这次比赛的结果")
- 定期系统优化 ("看看最近的题目哪里有问题")
- 大量 timeout/blocked 结果出现时
- 某类题（如 Cloud/Misc）解出率持续偏低时
