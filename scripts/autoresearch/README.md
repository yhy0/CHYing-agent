# Autoresearch: Claude CLI 驱动的自动诊断与优化

## 理念

传统的 ML 实验管理需要写大量编排代码：data loader、transcript analyzer、mutator、evaluator、result aggregator... 这些代码本身就是工程负担，而且一旦实验方向变了，编排代码也要跟着改。

Autoresearch 采用完全不同的思路：**不写编排代码，让 Claude CLI 自己执行整个研究循环**。

灵感来自 Andrej Karpathy 的 [autoresearch](https://github.com/karpathy/autoresearch) 实践。核心做法很简单：

1. 写一个 `program.md`，用自然语言定义研究协议（读什么文件、改什么代码、怎么验证、怎么决策）
2. 开一个 Claude Code 会话，说 "读 program.md，开始实验"
3. Claude 自己用 Bash/Read/Edit/Write/Grep/Glob 工具执行一切
4. 人可以随时介入审查和调整方向

这不是玩具。Claude CLI 有完整的文件系统访问、Shell 执行、代码编辑能力。它可以 `git checkout -b`、编辑 Markdown prompt 文件、运行 benchmark、读取结果、决定保留或回滚——整个循环不需要一行 Python 编排代码。

## 核心约束：禁止抄答案

**这是整个方案最重要的设计决策。**

Autoresearch 的目标是提升 agent 的**通用渗透测试能力**，不是为已知的 benchmark 题目植入答案。

Claude 在 Phase A 诊断时会读到每道失败题的详细日志——它知道 XBEN-042 是 Jinja2 SSTI，知道具体的攻击路径和 payload。如果不加约束，Claude 很可能写出这样的"优化"：

```
FORBIDDEN -- 这是在抄答案:
"When you see a Python web application with template rendering, use the payload:
{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}"
```

这种改动只是在记忆 benchmark 答案，对任何新题目毫无帮助。正确的改动应该是：

```
ALLOWED -- 这是通用能力提升:
"When HTML output reflects user input and the response contains template-like syntax
(e.g., Jinja2, Mako, Twig patterns), always test for Server-Side Template Injection (SSTI).
Use polyglot probes like {{7*7}}, ${7*7}, #{7*7} to identify the template engine before
crafting engine-specific payloads."
```

program.md 中定义了完整的防过拟合机制：

- **Blindfold Test**: 改动对一组完全不同的 104 道 CTF 题是否同样有帮助？如果只因为知道当前 benchmark 的具体题目才有效，就是过拟合。
- **Benchmark Fingerprint Check**: 改动中不能出现任何 benchmark ID (`XBEN-xxx`)。
- **抽象层级要求**: 诊断可以具体（"XBEN-042 没试 SSTI"），但改动必须抽象到**漏洞类别 + 通用检测启发式**。
- **每次 commit 前强制自检**。

## 六层优化空间

不只是 prompt。Autoresearch 覆盖六个优化层：

| 层 | 文件 | 可调内容 | 风险 |
|----|------|---------|------|
| **1. Prompt** | `chying_agent/prompts/*.md` | 13 个 Markdown prompt 文件，直接编辑 | 低 |
| **2. 反思阈值** | `claude_sdk/reflection.py` | 7 个数值参数（何时触发反思） | 低 |
| **3. 反思行为** | `claude_sdk/reflection.py` | 什么算进展、扣分表、提醒间隔 | 中 |
| **4. 引导循环** | `claude_sdk/base.py` | 置信度阈值、续跑轮数、重复检测 | 中 |
| **5. 工具配置** | `claude_sdk/mcp_tools.py` | 输出截断长度、超时、RAG top_k | 低 |
| **6. 子代理配置** | `brain_agent/claude_advisor.py` | 工具列表、描述文本、max_turns | 中 |

Prompt 抽离到 `.md` 文件后，编辑 prompt 不再有 Python 语法风险——这是最安全、最频繁的优化操作。

## 为什么这比 Python 编排脚本好

| 对比维度 | Python 编排 | Autoresearch |
|---------|------------|-------------|
| 开发成本 | 需要写 data_loader / transcript_analyzer / mutator / evaluator 等 10+ 模块 | 只写一个 program.md |
| 灵活性 | 固定流程，改方向就要改代码 | Claude 读到诊断结果后自主决定下一步 |
| 迭代速度 | 改代码 -> 测试 -> 再改 | 改 program.md 一行就能调整策略 |
| 判断能力 | 需要手写分类规则、阈值、启发式 | Claude 直接读 agent 日志，用 LLM 理解力分析根因 |
| 意外处理 | 遇到未预料的情况就崩 | Claude 能即兴应对，做出合理判断 |

## 工作原理

### 两阶段流程

```
Phase A: 诊断
  benchmark 结果 (JSON)
  + agent 工作日志 (progress.md / findings.log / reflection_history.md)
  -> Claude 分析根因、分类、找共性
  -> 输出 diagnosis_report.md (排序的改进假设)
  -> 每个假设标注目标优化层 (prompt / reflection / guidance / tool / subagent)

Phase B: 优化循环 (无限重复)
  读 diagnosis_report.md
  -> 选最高优先级假设
  -> git branch
  -> 原子修改 (一个文件一处改动)
  -> 防过拟合自检 + 语法验证
  -> 跑子集 benchmark (目标题 + canary 题)
  -> 读结果，判断 KEEP / DISCARD
  -> KEEP 则 push 到 origin
  -> 记录到 experiments.tsv
  -> 下一个假设
```

### 安全机制

- **防过拟合**: 改动不能包含 benchmark ID、具体 flag、特定 payload，必须是通用策略改进
- **文件白名单**: 允许修改 prompt、反思配置、引导循环参数、工具配置、子代理定义；核心逻辑禁止触碰
- **原子改动**: 每次实验只改一个文件的一处，确保结果可归因
- **Canary 回归检测**: 每次实验都会跑 5 道已解出的题，任何一道从 PASS 变 FAIL 就自动回滚
- **Git 隔离**: 每个实验在独立分支上进行，DISCARD 时直接删除分支
- **成本上限**: Claude CLI 的 `--max-budget-usd` 参数提供硬性成本控制
- **KEEP 自动 push**: 有效改动立即 push 到 origin，防止本地丢失

## Prompt 架构

所有 prompt 从 Python 字符串迁移到 `chying_agent/prompts/` 目录下的 `.md` 文件：

```
chying_agent/prompts/
    __init__.py                    # load_prompt() 函数
    orchestrator_identity.md       # Orchestrator 角色身份
    orchestrator_strategy.md       # 工具选择策略
    orchestrator_constraints.md    # 行为约束规则
    orchestrator_output.md         # 输出 JSON schema
    prompt_compiler.md             # PromptCompiler 系统提示词
    executor.md                    # 执行器子代理
    browser.md                     # 浏览器子代理
    c2.md                          # C2 后渗透子代理
    reverse.md                     # 逆向工程子代理
    scene.md                       # 场景管理
    scraper.md                     # 题目爬取
    writeup.md                     # Writeup 生成
    flag_submitter.md              # Flag 提交
```

原 `.py` 文件（如 `agents/executor_agent.py`）变为简单的 loader：
```python
from ..prompts import load_prompt
EXECUTOR_AGENT_SYSTEM_PROMPT = load_prompt("executor.md")
```

## 文件结构

```
scripts/autoresearch/
    README.md               # 本文档
    program.md              # 研究协议 (Claude 的 "程序")
    CLAUDE.md               # 工作区级指令 (Claude CLI 自动读取)
    diagnosis_report.md     # Phase A 输出 (Claude 生成)
    experiments.tsv         # Phase B 实验记录 (Claude 生成)
```

## 使用方法

### 前置条件

1. 独立仓库副本已创建（clone 一份，复制 benchmark 数据 + agent-work + .env，`uv sync`）
2. 已有 benchmark 运行结果: `benchmark/glm-5-state.json`
3. 已有 agent 工作日志: `agent-work/ctf/Web/` 下的归档目录
4. Claude CLI 已安装并配置

### Phase A: 诊断 (一次性)

分析所有失败的 benchmark，找出根因和共性模式。

```bash
cd CHYing-agent-autoresearch

# 交互模式 (推荐，可以中途审查)
claude --dangerously-skip-permissions
> 读 scripts/autoresearch/program.md，执行 Phase A 诊断流程

# 或非交互模式 (后台运行)
claude --dangerously-skip-permissions \
    --max-budget-usd 50 \
    -p "读 scripts/autoresearch/program.md，执行 Phase A 诊断流程"
```

完成后检查 `scripts/autoresearch/diagnosis_report.md`，确认：
- 根因分类是否合理
- 改进假设是否有针对性
- **改进假设是否通用（不是在抄答案）**
- 假设是否覆盖了不同的优化层（不要全是 prompt 改动）
- Canary 集合是否覆盖不同类型

### Phase B: 优化循环 (长时间运行)

逐个测试改进假设，用 benchmark 验证效果。

```bash
# 交互模式 (推荐，可以中途干预)
claude --dangerously-skip-permissions
> 读 scripts/autoresearch/program.md，执行 Phase B 优化循环

# 或后台运行
nohup claude --dangerously-skip-permissions \
    --max-budget-usd 300 \
    -p "读 scripts/autoresearch/program.md，执行 Phase B 优化循环" \
    > autoresearch.log 2>&1 &
```

### 关键 flag 说明

| Flag | 作用 |
|------|------|
| `--dangerously-skip-permissions` | 跳过所有权限确认，让 Claude 自主执行 Bash/Edit/Write |
| `--max-budget-usd N` | 成本上限保护，达到后 Claude 自动停止 |
| `-p "..."` | 非交互模式，适合 `nohup` 后台运行 |

不加 `-p` 的交互模式更推荐，因为：
- 可以中途审查 Claude 的诊断结论
- 可以检查改动是否在"抄答案"
- 可以调整实验优先级
- 可以在看到某个方向没希望时提前转向

### 查看进度

```bash
# 查看实验记录
cat scripts/autoresearch/experiments.tsv

# 查看当前分支
git branch | grep autoresearch

# 审查改动是否通用
git diff main -- chying_agent/

# 查看诊断报告
cat scripts/autoresearch/diagnosis_report.md
```

### 中途干预

交互模式下，直接对 Claude 说：

- "跳过当前假设，试下一个"
- "这个方向不对，重新跑 Phase A 诊断"
- "这个改动太针对具体题目了，重新想一个更通用的方案"
- "试试调反思阈值，不要只改 prompt"
- "停下来，让我看看当前的改动"

## benchmark_runner.py 的改动

为了支持子集运行，`benchmark_runner.py` 新增了 `--challenges` 参数：

```bash
uv run python scripts/benchmark_runner.py \
    --challenges XBEN-001-24,XBEN-005-24,XBEN-010-24
```

这是整个 autoresearch 方案唯一的 benchmark 代码改动。

## 实验记录格式

`experiments.tsv` 记录每次实验的结果：

```
ID      Description                     File                            Target  Canary  Result  Time
H001    Add SQLi detection hint         prompts/orchestrator_strategy.md 3/5    5/5     KEEP    2026-03-26T10:00
H002    Lower no_progress_threshold     claude_sdk/reflection.py         0/4    5/5     DISCARD 2026-03-26T12:30
H003    Add SSTI polyglot probing       prompts/executor.md              2/3    5/5     KEEP    2026-03-26T15:00
H004    Raise SUBAGENT_MAX_TOOL_USES    claude_sdk/base.py               1/4    5/5     KEEP    2026-03-26T18:00
```

## 局限性

- **成本**: 每个 benchmark 题目需要 3-25 USD，一轮子集测试 (10 题) 约 50-150 USD
- **时间**: 每个题目 5-35 分钟，一轮子集测试约 1-3 小时
- **搜索空间**: 不触碰核心架构（hook 系统、session 管理、stream 处理）
- **局部最优**: 单变量实验可能错过需要多个改动配合才能生效的优化
- **模型依赖**: 诊断质量取决于 Claude 对 CTF 日志的理解能力
- **过拟合风险**: 尽管有防护机制，仍需人工审查改动是否真正通用

这些局限是有意为之。Autoresearch 的价值在于**零开发成本的快速迭代**，而不是穷举搜索空间。
