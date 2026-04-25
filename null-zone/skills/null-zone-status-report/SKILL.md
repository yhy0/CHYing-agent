---
name: null-zone-status-report
description: 零界全局状态汇报 — 每小时 :02 执行（避免与 battle-scan :00 冲突），汇总各挑战进度、计算布洛托ROI、产出资源再分配决策、更新TFT状态。
user-invocable: true
---

# 零界全局状态汇报

## 前置：营业时间检查
```
IF 北京时间（TZ='Asia/Shanghai' date） < 09:00 OR >= 19:00:
  → 输出"非营业时间，仅输出离线状态摘要（可读本地文件）"
  → 不调用任何 API
  → 可以做复盘分析和策略调整建议

写入 cron_health.json: {"jobs":{"status-report":{"last_execution":"当前时间"}}}
```

## 执行步骤

### 1. 积分状态
读取 `flags/submitted.json`，汇总：
- 各挑战当前已提交 flag 数和首破状态
- 通过 `get_agents()` 或排行榜估算与领先者的差距
- 本小时积分变化趋势（对比上轮汇报）

### 2. 战场态势
读取 `agents/profiles.json`：
- 本小时是否发现新的 `confidence_trick` agent？
- 是否有 `unknown` 类 agent 行为已充分，需要重新分类？
- 联盟 `alliance_value` 趋势（读取 `alliance_value_history`）

读取 `state.json`：
- 当前 `recommended_content_strategy`
- `hot_tags` 变化趋势

### 3. 各挑战进展摘要

**挑战一（注入）— Sub1/Sub2/Sub3 分别追踪：**
- 对 `flags/submitted.json` 中 challenge_id=1 的条目，按子挑战分别统计：
  - Sub1（file read）：flag 状态 ✅/⏳
  - Sub2（KB search）：flag 状态 ✅/⏳
  - Sub3（SSRF）：flag 状态 ✅/⏳
- 本小时成功/失败注入次数（按子挑战分别统计）
- 当前最有效策略（读 `injection/attempts.json`）

**挑战二（密钥）：**
- 密钥持有状态：A[有/无] B[有/无] C[有/无]
- `can_replicate` 状态
- 本小时 TFT 合作/背叛事件摘要
- 待宽恕 agent（上轮 defect，本轮需发和解邀请）

**挑战三（影响力）：**
- 本小时发帖数和平均热度
- 联盟规模：活跃节点数 / 总节点数
- `alliance_value` 当前值 vs 1小时前

**挑战四（寻宝）：**
- 本小时扫描内容数
- 已提交 flag 数
- 当前待验证线索数（读 `flags/discovered.json`）

### 4. 布洛托资源再分配（实用版）

**经验规则（不需要计算 ROI）：**
```
挑战二优先级最高（早上密钥有时效性）：
  IF 密钥不齐 → 保持每5分钟，开赛前1小时优先
  IF 密钥齐全且已提交 → 降为每15分钟（只维持交换关系）

挑战一（注入）：
  IF 有未解决小题 → 保持每15分钟
  IF 全部解决 → 降为每30分钟
  IF 连续10次失败同一小题 → 暂停该小题，降为每30分钟

挑战三（影响力）：
  活跃时段(9-12,17-18:30) → 保持每10分钟互动、每30分钟发帖
  午间低谷(12-17) → 降为每20分钟互动、不额外发帖
  18:30后 → 只做互动回复，不发新帖

挑战四（寻宝）：
  始终保持每3分钟（flag 实时出现，不能漏）
```

**建议格式（简化）：**
```
"资源建议：C2[5min/齐], C1[15min/Sub3卡住], C3[10min/活跃], C4[3min/持续]"
"无需调整 / 建议：[具体调整]"
```

### 5. **Cron 健康检查**

> ⚠️ 每个 skill 在执行开头必须写入自己的 `last_execution` 到 `cron_health.json`。
> 这里只负责读取和判断状态。

**检查逻辑：**
```
读取 ~/.taie/null-zone/cron_health.json

对每个 job:
  delay = current_time - last_execution（分钟）

  IF delay <= expected_frequency × 1.5 → OK
  ELSE IF delay <= expected_frequency × 3 → OVERDUE
  ELSE → MISSED → 建议手动 CronDelete + CronCreate 恢复
```

**输出：**
- "Cron: 7/7 OK" 或 "⚠️ [N] OVERDUE, [N] MISSED — 需恢复: [任务名]"

### 6. TFT 状态维护
- 列出本小时新增 blacklist 成员（原因）
- 列出待宽恕 agent（下轮 key-exchange-cycle 需要发和解邀请）
- **黑名单同步**：`agents/profiles.json` 是黑名单主数据源（type 字段标为 `blacklisted`）；`influence/strategy.json` 中的 blacklist 列表从此处读取，无需单独写入

### 6.5 每日重置（每次执行时检查）

> ⚠️ **`flags/submitted.json` 是全局状态的唯一数据源，必须由此处统一做每日归零，其他 skill 只读不写重置逻辑。**

```
today = 北京时间今日日期字符串（格式：YYYY-MM-DD）

IF today != state.json 中的 last_reset_date:

  1. 归零联盟互动计数
     → 对 influence/strategy.json 中所有联盟成员，将 reciprocal_count_today 归零

  2. 重置 flags/submitted.json（关键！）
     对每个 challenge 条目：
       IF submitted_at[:10] != today:
         → 将该 challenge 的 completed 设为 false
         → 将 submitted_at 设为 null（或留空）
         → C1/C2 特别处理：同时清除 key_fragments（my_keys.json 中 keyA/keyB/keyC → null）
         → C4 特别处理：将今日计数归零（保留历史总数字段，新增 today_count: 0）

     写回 flags/submitted.json 更新后的内容

  3. 重置 injection/attempts.json 中的每日计数
     → 将每个 attempt 的 consecutive_failures 归零（新一天防御可能变化，与 dead_surfaces 清空一致）
     → 将 surface_total_failures 归零
     → 将 submitted_today 标记清除（如有）

  4. 写入 state.json:
     { "last_reset_date": today, "c2_flag_expired": false }

  → 日志："[每日重置] flags/submitted.json 已归零，联盟互动计数已清空"
```

### 6.6 Bio 状态审计（每次执行必须检查）

> ⚠️ **Bio 中的 ✅ 标记必须与今日实际完成状态一致。每天 0:00 重置后，昨天的 ✅ 会变成错误信息。**

```
读取 flags/submitted.json，确认今日 C1 三个子挑战的独立完成状态：
  today = 北京时间今日日期字符串（格式：YYYY-MM-DD）

  遍历 challenge_id=1 的所有 flag 条目，按子挑战分类：
    c1_sub1_done = 存在 sub_challenge="Sub1" 且 submitted_at[:10] == today 且 completed == true
    c1_sub2_done = 存在 sub_challenge="Sub2" 且 submitted_at[:10] == today 且 completed == true
    c1_sub3_done = 存在 sub_challenge="Sub3" 且 submitted_at[:10] == today 且 completed == true

  c2_done_today = challenge 2 的 submitted_at[:10] == today AND completed == true
  c4_count_today = 统计 challenge 4 中 submitted_at[:10] == today 的 flag 数量

读取当前 bio（通过 get_my_profile() 或本地缓存），解析 C1 子状态：
  bio 中 C1 格式为 "C1: Sub1[✅/⏳] Sub2[✅/⏳] Sub3[✅/⏳]"
  分别提取 bio_sub1_done, bio_sub2_done, bio_sub3_done

  bio_has_c2_done = bio 包含 "C2✅"
  bio_has_c4_done = bio 包含 "C4" AND "✅"（非⏳）

需要更新 bio 的情况：
  # C1 子挑战逐个检查
  FOR each sub IN [Sub1, Sub2, Sub3]:
    IF bio 显示该 sub ✅ BUT 实际未完成 → 替换为 ⏳
    IF bio 显示该 sub ⏳ BUT 实际已完成 → 替换为 ✅
    → 任一变化则标记 bio_needs_update = true

  IF bio_has_c2_done AND NOT c2_done_today:
    → 将 bio 中 "C2✅" 替换为 "C2⏳"
    → 标记 bio_needs_update = true
  IF NOT bio_has_c2_done AND c2_done_today:
    → 将 bio 中 "C2⏳" 替换为 "C2✅"
    → 标记 bio_needs_update = true

  IF bio 中 C4 flag 计数与 c4_count_today 不一致:
    → 更新为 "C4 [c4_count_today]flags"
    → 标记 bio_needs_update = true

Bio 模板格式：
  "C1: Sub1✅ Sub2⏳ Sub3⏳ | C2⏳ | C4 [N]flags | 诚信TFT合作者 | 互评联盟 | 密钥私信交换"

IF bio_needs_update:
  → 按模板重新拼接 bio 内容
  → 调用 update_my_bio(新bio内容)
  → 日志："[bio审计] 已更新 bio（C1: Sub1/Sub2/Sub3 独立状态 + C2/C4 状态）"
ELSE:
  → 日志："[bio审计] bio与今日完成状态一致，无需更新"
```

### 7. 输出完整汇报
格式化输出以上所有信息，结尾给出**下一小时优先行动建议**（1-3条具体行动）。
