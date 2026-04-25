# CLAUDE.md — Agent Workspace

## Post-Compact Recovery

If you are unsure about your current task, target, or progress after a compact:

> 使用**绝对路径**读取以下文件（文件在当前 challenge 的工作目录下，不是 agent-work 根目录）。
> 当前工作目录可从系统消息或 `progress.md` 的路径推断。

1. **Read `progress.md`** — 主恢复文件；优先看 `Compiled Task Context` / `Attack Tree` / `Dead Ends` / `Current Phase` / `Next Steps`
2. **Read `findings.log`** — 关键发现与证据账本，重点看 `next_action` / `paths_not_tried` / 验证状态
3. **If present, read `hint.md`** — 比赛提示工具 `view_hint` 的持久化记录（append-only）
4. **Only if needed, read `attack_timeline.md`** — 用于追溯某个 key/命令结果的来源、执行顺序、环境差异
   > ⚠️ 其中 `[分析]` 标签行是模型的推断/叙事，可信度低于工具调用结果行和 `findings.log`。
   > 只有在 `progress.md` / `findings.log` 无法解释某个事实来源时再读 timeline。
5. **NEVER delete the "Compiled Task Context" section** in progress.md

特别注意：检查之前使用的执行环境（WSS远程终端 vs docker本地），
通过远程环境获取的凭证/会话可能只在远程网络中有效。

progress.md sections:
- "Compiled Task Context" — auto-generated at start, DO NOT modify
- "Attack Tree" — auto-synced from record_key_finding (title + evidence per entry, supports updates)
- "Dead Ends" — auto-synced from record_key_finding(kind="dead_end") and structured output flush, DO NOT retry
- "Current Phase" — auto-synced from TodoWrite and structured output
- "Next Steps" — auto-synced from structured output before compact
- "Key Artifacts" — auto-synced from structured output / subagent artifact_paths / hint persistence
- "Hints Used" — auto-synced from view_hint and hint.md

Then resume work based on this information.

## Key Behaviors (may be lost after compact)

- Redirect large output to files (`cmd > /tmp/out.txt 2>&1`), do NOT print into conversation
- Persist key discoveries via `record_key_finding`, not just conversation text
- Use `take_snapshot` instead of `take_screenshot` (screenshot is blocked)


