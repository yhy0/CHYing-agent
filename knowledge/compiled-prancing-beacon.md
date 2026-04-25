# CTF Agent: 去掉 RAG，用 Knowledge Base 替代

## Context

**问题**: 当前 RAG 系统（embedding + BM25 混合检索 2861 篇 markdown）在比赛环境下（8GB 内存）消耗 ~1.2GB，且每次都"重新理解世界"——检索不准、上下文过长、无法积累经验。

**思路**: 受 Karpathy "LLM Knowledge Bases" 启发——不要临时检索文档片段，而是把知识提前编译成结构化的、互链的 wiki 页面。CTF 题型可枚举（~60-80 种技术），一套 markdown wiki 就够覆盖 95% 的题。

**核心决策**:
1. **去掉 RAG**——不要 embedding 模型、不要向量计算、不要 BM25、不要独立 RAG service 进程
2. **wiki 页面是 markdown**——不是 rigid YAML schema，是写给人和 LLM 都能读的知识文档
3. **匹配器极简**——只读 frontmatter 关键词匹配，~50 行代码
4. **我直接编译知识页面**——不需要 compiler.py 调 API
5. **完整 Obsidian 工作流**——CLAUDE.md / index.md / log.md / ingest / query / lint

---

## 新目录结构

```
chying_agent/rag/
├── knowledge_base/           # 【保留但运行时不加载】原始文档，只读原料
│
├── compiled_kb/              # 【新增】Obsidian vault — 编译后的知识库
│   ├── CLAUDE.md             # vault 的编译规范
│   ├── index.md              # 全局目录
│   ├── log.md                # 操作日志（只增不减）
│   │
│   ├── techniques/           # wiki 技术页面 (markdown)
│   │   ├── pwn/
│   │   │   ├── ret2libc.md
│   │   │   ├── format_string.md
│   │   │   ├── rop_chain.md
│   │   │   └── ...
│   │   ├── web/
│   │   │   ├── sqli.md
│   │   │   ├── ssti.md
│   │   │   └── ...
│   │   ├── crypto/
│   │   ├── cloud/
│   │   └── misc/
│   │
│   └── experience/           # 解题原始记录（raw sources for future ingest）
│       ├── 2026-04-07_ret2libc_xxx.md
│       └── ...
│
├── compiled_kb.py            # 【新增】KB 加载器 + frontmatter 关键词匹配（~100 行）
├── knowledge_base.py         # 【保留文件但不再运行时加载】旧检索引擎
├── rag_service.py            # 【大改】去掉 embedding/BM25，只服务 KB
├── client.py                 # 【大改】去掉 HTTP 调用，直接 import CompiledKB
└── __init__.py               # 【改】导出新接口
```

---

## wiki 页面格式

每个技术页面是一篇 **markdown + YAML frontmatter**：

```markdown
---
category: pwn
tags: [ret2libc, rop, libc, stack_overflow, nx_bypass, aslr]
triggers: [buffer overflow, ret2libc, NX enabled, libc, 栈溢出, got表泄露]
related: [rop_chain, format_string, one_gadget, ret2csu, stack_pivot]
---

# Return-to-libc 攻击

## 什么时候用
栈溢出 + NX 开启（不能直接执行 shellcode）+ 链接了 libc。

## 前提条件
- 可以控制返回地址
- NX 开启（否则直接 shellcode，见 [[shellcode_injection]]）
- 有 libc leak 途径（puts/printf GOT 可读，或 [[format_string]] leak）
- ⚠️ Full RELRO 时 GOT 只读，需要其他方式

## 攻击步骤
### 1. 找偏移
...（含代码）

### 2. 泄露 libc 地址
...（含代码）

### 3. 计算基地址 + 发送 shell payload
...（含代码）

## 常见坑
- 栈对齐问题（x86_64 需 16 字节对齐）
- libc 版本不匹配
- ...

## 变体
- 32 位 vs 64 位差异
- 没有直接 leak 时用 [[ret2csu]]
- ROP 空间不够时用 [[stack_pivot]]

## 相关技术
- [[rop_chain]] — ROP 基础
- [[format_string]] — 另一种 leak 方式
- [[one_gadget]] — 约束满足时的捷径
```

关键特点：
- **frontmatter** 只放机器匹配需要的字段（tags / triggers / category / related）
- **正文**是知识，不是填表——有判断（"什么时候用"）、有上下文（"为什么"）、有代码
- **`[[wiki-links]]`** 做交叉链接，Obsidian 图谱可视化

---

## 核心新增：`compiled_kb.py`（~100 行）

```python
"""
CompiledKB — 极简的 markdown wiki 加载器 + frontmatter 关键词匹配。

Karpathy: "index.md works surprisingly well at moderate scale
(~100 sources, ~hundreds of pages) and avoids the need for
embedding-based RAG infrastructure."
"""

class CompiledKB:
    """加载 compiled_kb/techniques/ 下的 markdown 页面，
    通过 frontmatter 的 tags + triggers 做关键词匹配。"""

    def __init__(self, kb_dir: str):
        self.pages: dict[str, PageMeta] = {}  # page_id -> metadata
        self.contents: dict[str, str] = {}     # page_id -> full markdown
        self._load(kb_dir)

    def _load(self, kb_dir: str):
        """扫描 techniques/**/*.md，解析 YAML frontmatter。"""
        for md_file in Path(kb_dir, "techniques").rglob("*.md"):
            page_id = md_file.relative_to(Path(kb_dir, "techniques"))
                             .with_suffix("").as_posix()  # "pwn/ret2libc"
            frontmatter, content = parse_frontmatter(md_file)
            self.pages[page_id] = PageMeta(
                category=frontmatter.get("category", ""),
                tags=[t.lower() for t in frontmatter.get("tags", [])],
                triggers=[t.lower() for t in frontmatter.get("triggers", [])],
            )
            self.contents[page_id] = content

    def match(self, query: str, category: str = "", top_k: int = 5
              ) -> list[tuple[str, float]]:
        """关键词匹配，返回 [(page_id, score)]。"""
        query_lower = query.lower()
        scores = {}
        for page_id, meta in self.pages.items():
            score = 0.0
            for tag in meta.tags:
                if tag in query_lower:
                    score += 10.0
            for trigger in meta.triggers:
                if trigger in query_lower:
                    score += 5.0
            if category and meta.category == category.lower():
                score += 3.0
            if score > 0:
                scores[page_id] = score
        ranked = sorted(scores.items(), key=lambda x: -x[1])
        return ranked[:top_k]

    def get_content(self, page_id: str) -> str | None:
        return self.contents.get(page_id)

    @property
    def page_count(self) -> int:
        return len(self.pages)
```

内存占用：~50-80 篇 markdown 页面 ≈ **3-5MB**（vs RAG 的 1.2GB）。

---

## 经验积累：两层分离

| 层 | 目录 | 内容 | 增长方式 |
|---|---|---|---|
| **原始记录** | `compiled_kb/experience/` | 每次解题的日志 | 自动追加，不限增长 |
| **wiki 页面** | `compiled_kb/techniques/` | 编译后的知识 | 我来 ingest 编译，只更新不堆积 |

流程：
```
Agent 解题 → 写 experience/2026-04-07_ret2libc_xxx.md（自动）
           → 积累 N 条后，用户让我 ingest
           → 我读经验记录，提炼有价值信息
           → 更新 ret2libc.md 的"常见坑"或"变体"段落（重写整合，不是追加）
           → 更新 log.md
```

经验记录的写入只需要一个简单函数（~30 行），不需要独立模块：

```python
def record_experience(kb_dir: str, technique_id: str, challenge_name: str,
                      solved: bool, notes: str):
    """写一条解题经验到 experience/ 目录。"""
    exp_dir = Path(kb_dir) / "experience"
    exp_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    slug = technique_id.replace("/", "_")
    path = exp_dir / f"{timestamp}_{slug}.md"
    content = f"""---
technique: {technique_id}
challenge: {challenge_name}
solved: {solved}
date: {timestamp[:10]}
---

# {challenge_name}

匹配技术: [[{technique_id}]]
结果: {"✅ 成功" if solved else "❌ 失败"}

## 笔记
{notes}
"""
    path.write_text(content, encoding="utf-8")
```

---

## 现有文件改造

### `rag_service.py` — 两个选项

**选项 A（推荐）：去掉独立 service，CompiledKB 内嵌到 Agent 进程**

KB 只有 ~5MB 内存，不需要独立进程。直接在 Agent 启动时加载：

```python
# 在 Agent 初始化时
from chying_agent.rag.compiled_kb import CompiledKB
compiled_kb = CompiledKB(kb_dir="chying_agent/rag/compiled_kb")
```

`rag_service.py` 可以保留但默认不启动。如果未来有需要（多 Agent 共享 KB），再启用。

**选项 B：保留 FastAPI 但极大简化**

去掉所有 embedding/BM25 相关代码，只保留 `/kb/search` 和 `/kb/page/{id}` 两个端点。

### `client.py` — 重写（~80 行）

去掉 HTTP 调用，直接操作 CompiledKB 实例：

```python
"""Knowledge Base 客户端 — 替代原 RAG client。"""

_kb: CompiledKB | None = None

def _get_kb() -> CompiledKB | None:
    global _kb
    if _kb is None:
        kb_dir = Path(__file__).parent / "compiled_kb"
        if kb_dir.exists():
            _kb = CompiledKB(str(kb_dir))
    return _kb

async def query_knowledge(
    name: str = "", category: str = "", hint: str = "",
    description: str = "", top_k: int = 5,
) -> list[dict]:
    """替代 query_rag()。返回格式兼容旧接口。"""
    kb = _get_kb()
    if not kb:
        return []
    query = " ".join(filter(None, [name, category, hint, description]))
    matches = kb.match(query, category=category, top_k=top_k)
    results = []
    for page_id, score in matches:
        content = kb.get_content(page_id)
        results.append({
            "id": page_id,
            "source_id": page_id,
            "section": "",
            "partition": page_id.split("/")[0],  # "pwn", "web", ...
            "score": score,
            "snippet": content or "",
        })
    return results

def format_knowledge_for_prompt(results: list[dict]) -> str | None:
    """格式化给 Agent 的完整知识注入。"""
    if not results:
        return None
    parts = []
    for r in results:
        parts.append(f"## 📖 {r['source_id']} (匹配度: {r['score']:.0f})\n")
        parts.append(r["snippet"])
        parts.append("\n---\n")
    return "\n".join(parts)

def format_knowledge_for_compiler(results: list[dict]) -> str | None:
    """精简版给 PromptCompiler（只取前 500 字 + 标题结构）。"""
    if not results:
        return None
    parts = []
    for r in results:
        content = r["snippet"]
        # 取前 500 字 + 保留标题结构
        summary = _extract_summary(content, max_chars=500)
        parts.append(f"- **{r['source_id']}**: {summary}")
    return "\n".join(parts)
```

### `__init__.py` — 改导出

```python
# 旧接口保留但指向新实现（向后兼容）
from .client import query_knowledge as query_rag  # alias
from .client import query_knowledge

__all__ = ["query_rag", "query_knowledge"]
```

**关键**: `query_rag` 作为 alias 保留，返回格式兼容 `list[dict]`，这样 3 个调用方 **不需要改任何代码** 就能切换。

---

## 3 个调用方的改动

### 调用方 1: `brain_agent/prompt_compiler.py`（_query_rag, line 61-97）

**改动**: 0 行。因为 `__init__.py` 把 `query_rag` alias 到了 `query_knowledge`，现有代码自动生效。

如果想优化格式，可以把 `format_rag_results_for_compiler` 换成 `format_knowledge_for_compiler`（~2 行改动）。

### 调用方 2: `challenge_solver.py`（line 978-1001）

**改动**: 0 行。同上，`from chying_agent.rag import query_rag` 自动指向新实现。

### 调用方 3: `claude_sdk/mcp_tools.py` — rag_search 工具（line 985-1055）

**改动**: ~5 行。改工具名称和描述，让 Agent 知道这是 KB 搜索：

```python
@mcp_tool(
    name="kb_search",                    # 改名
    description="搜索技术知识库...",        # 改描述
    ...
)
```

内部逻辑不变——还是调 `query_rag()`（alias），格式化，返回。

---

## Obsidian 工作流

### CLAUDE.md（vault 的编译规范）

```markdown
# CTF Knowledge Base — 编译规范

## 目录结构
- techniques/ — 技术页面（只有我编译的产物）
- experience/ — 解题原始记录（只读原料）

## 页面 ID 规范
- 格式: {category}/{slug}，如 pwn/ret2libc, web/sqli
- slug: 小写，下划线分隔

## frontmatter 规范
- category: pwn | web | crypto | misc | reverse | forensics | cloud
- tags: 小写，机器匹配用（技术关键词，中英双语）
- triggers: 题目中可能出现的关键词/短语
- related: 相关页面的 slug 列表

## Ingest 流程
1. 读原始文档（knowledge_base/ 或 experience/）
2. 提炼核心知识，写/更新 techniques/ 下的页面
3. 更新 index.md
4. 追加 log.md

## 铁律
- 原始文档永远不改
- wiki 页面只更新不堆积（新认知替换旧段落）
- 矛盾不覆盖，标注 ⚠️ 矛盾 等人确认
```

### index.md（全局目录）

```markdown
# 技术知识库索引

## PWN
- [[pwn/ret2libc]] — 栈溢出 + NX → 返回 libc system
- [[pwn/format_string]] — 格式化字符串读写任意地址
- [[pwn/rop_chain]] — ROP 基础概念和链构造
- ...

## WEB
- [[web/sqli]] — SQL 注入（union/blind/error/time）
- [[web/ssti]] — 服务端模板注入（Jinja2/Twig/Freemarker）
- ...
```

### log.md（操作日志）

```markdown
# 操作日志

## [2026-04-07] ingest | 初始编译
- 编译 pwn/ret2libc（源: ht_binary/rop*.md, Awesome-POC）
- 编译 web/sqli（源: ht_web/sql-injection*.md）
- ...
```

---

## 实施步骤

### Phase 1: 框架 + 种子页面
1. 创建 `compiled_kb.py` — KB 加载器 + 匹配器（~100 行）
2. 创建 `compiled_kb/` 目录结构 + `CLAUDE.md` + `index.md` + `log.md`
3. 我读 knowledge_base/ 原始文档，直接编译 5 张种子页面：
   - `pwn/ret2libc.md`
   - `web/sqli.md`
   - `web/ssti.md`
   - `pwn/format_string.md`
   - `web/deserialization_pickle.md`
4. 写 `record_experience()` 函数（~30 行，内嵌在 compiled_kb.py）

### Phase 2: 替换 RAG 接线
1. 重写 `client.py` — 去掉 HTTP 调用，直接用 CompiledKB（~80 行）
2. 改 `__init__.py` — `query_rag` alias 到 `query_knowledge`
3. 改 `mcp_tools.py` — rag_search → kb_search（~5 行）
4. 设 `RAG_ENABLED=false`（或直接不启动 rag_service）
5. `rag_service.py` 和 `knowledge_base.py` 保留文件但不再运行时加载

### Phase 3: 扩展编译
- 用户让我继续 ingest 更多技术页面
- 目标 ~50-80 页覆盖 95% CTF 题型
- 每次 ingest: 读原始文档 → 写/更新页面 → 更新 index → 追加 log

---

## 验证方式

1. **匹配测试**: `CompiledKB.match("buffer overflow NX enabled ret2libc")` → 命中 `pwn/ret2libc`
2. **兼容测试**: 现有 3 个调用方（prompt_compiler / challenge_solver / mcp_tools）不改代码，正常返回结果
3. **内存测试**: Agent 进程不再加载 embedding 模型，RSS 减少 ~1.2GB
4. **回退测试**: `compiled_kb/` 目录不存在时，`query_knowledge()` 返回 `[]`，Agent 正常运行
5. **Obsidian 测试**: 用 Obsidian 打开 `compiled_kb/`，图谱视图显示页面间 wiki-link 关系
6. **端到端**: 用一道 CTF 题跑完整流程——匹配 → 解题 → 记录经验
