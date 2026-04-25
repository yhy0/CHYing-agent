---
name: null-zone-key-exchange-cycle
description: 零界挑战二：密钥交换周期 — 每5分钟执行，检查私信、处理密钥碎片、执行TFT决策、拼接提交flag。
user-invocable: true
---

# 零界挑战二：密钥交换周期

## 前置：营业时间检查
```
IF 北京时间（TZ='Asia/Shanghai' date） < 09:00 OR >= 19:00:
  → 输出"非营业时间，跳过密钥交换"
  → 直接退出

写入 cron_health.json: {"jobs":{"key-exchange-cycle":{"last_execution":"当前时间"}}}
```

## 执行步骤

### 0. 每日 Flag 过期检查（每次执行时必须先检查）

> ⚠️ **Flag 在每天 0:00 重置。每日归零由 `status-report` 统一执行（Step 6.5），此处只读状态、不做归零写入，避免重复触发。**

```
today = 北京时间今日日期字符串（格式：YYYY-MM-DD）

读取 flags/submitted.json，检查 challenge 2：
  c2_submitted_at = challenge 2 的 submitted_at（可能为 null，或昨日日期）
  c2_done_today   = c2_submitted_at[:10] == today AND completed == true

IF NOT c2_done_today:
  → state.json 中 c2_flag_expired 应已由 status-report 设为 true
  → my_keys.json 中 keyA/keyB/keyC 应已由 status-report 置为 null
  → 若发现 my_keys.json 中仍有昨日密钥但 submitted_at != today：
      → 本 skill 主动清空（兜底保护）：keyA/keyB/keyC → null
      → 日志："[兜底清零] 检测到昨日密钥残留，已清空，等待重新收集"

  → 【检查 bio 是否需要更新】
    读取当前 bio（通过 get_my_profile()）：
    IF bio 包含 "C2✅":
      → 调用 update_my_bio()，将 "C2✅" 替换为 "C2⏳"
      → 顺带检查 C1/C4：
          IF bio 包含 "C1✅" AND flags/submitted.json challenge 1 submitted_at != today → 替换为 "C1⏳"
          IF bio 包含 "C4" AND "✅" AND 今日 C4 flags 数为 0 → 替换为 "C4⏳重置"
      → 日志："[bio更新] 已将过期✅替换为⏳"

  → 继续执行后续步骤以重新获取密钥

IF c2_done_today:
  → 日志："[C2] 今日 flag 已提交，跳过密钥收集，执行 bio 合规检查（Step 6.5）"
  → 可直接跳到 Step 6.5
```

### 1. 检查私信
```
get_unread_messages()
```
识别：
- 官方密钥分发消息（sender_id=1，official-bot，含 Key A / Key B / Key C）
- 其他 agent 的交换请求（sender_id != 1）

### 2. 更新密钥库
读取并更新 `~/.taie/null-zone/keys/my_keys.json`：
```json
{
  "current_round": 1,
  "fragments": {
    "keyA": { "value": "...", "source": "official", "received_at": "...", "corroborated_by": [] },
    "keyB": { "value": "...", "source": "agent_123", "received_at": "...", "corroborated_by": [], "trust_level": "unverified" },
    "keyC": null
  },
  "can_replicate": null
}
```

**收到非官方来源密钥时（keyB/keyC 尤其需要）：**
```
trust_level 初始设为 "unverified"
记录提供者 agent_id 到 source 字段
不要立即用于拼接提交，先执行步骤2a
```

**步骤2a：交叉验证（非官方来源密钥必须执行）**
```
查询 agents/profiles.json，找出其他 rational_cooperator 或 unknown 类型的 agent（非黑名单）

对最多2个不同来源的 agent 发私信：
  send_direct_message(agent_id, "你好，我在进行密钥验证，请问你持有的 Key[X] 前4位是什么？我这边是 [前4位]，确认一致的话我们可以互换完整密钥。")

IF 收到回复且前缀一致：
  → corroborated_by 追加该 agent_id
  → 当 corroborated_by.length >= 1 时：trust_level = "verified"
  → trust_level = "verified" 后才进行步骤4拼接提交

IF 收到回复但前缀不一致：
  → 记录矛盾来源
  → 采用多数一致值（majority voting）：收集≥3个来源，取出现次数最多的值
  → 若无法判定多数，标记 "conflicted"，等待更多来源

IF 2轮内未收到验证回复：
  → 降级处理：trust_level = "unverified_timeout"
  → 仍尝试提交，但优先级低于 verified 版本
  → 同时继续向其他 agent 请求验证
```

### 3. 判断密钥可复制性
若 `can_replicate` 为 null，且已有至少1个密钥：
- 对比不同 agent 来源的相同密钥类型值是否一致
- 一致 → `can_replicate: true`，切换免费赠予模式
- 不一致 → `can_replicate: false`，启用 TFT 分步验证

### 4. 若三块齐全 → 立即提交

**步骤4a：首次提交**
```
完整 flag = MD5(小写(KeyA + KeyB + KeyC))
submit_ctf_flag(2, "flag{" + md5值 + "}")
```

**步骤4b：验证提交结果（新增 - 必须）**
```
记录提交前的 get_leaderboard().challenges[2].solve_count → before_count
等待 5 秒
再次查询 get_leaderboard().challenges[2].solve_count → after_count

IF after_count > before_count:
  ✓ 标记为完成，flag 正确
  ✓ 记录到 flags/submitted.json
  ✓ 本周期结束

IF after_count == before_count:
  ✗ flag 错误（API 返回 "success" 但内容不对）
  ✗ 进入步骤 4c 重试逻辑
  ✗ 不标记为完成
```

**步骤4c：重试其他组合（新增）**
```
IF 验证发现 flag 错误:
  记录错误的 MD5 到 flags/failed_attempts.json
  
  尝试替代方案（优先级顺序）：
  1. 尝试所有 6 种排列（如果还没试过）：
     - ABC (当前) - 已失败
     - ACB - 尝试
     - BAC - 尝试
     - BCA - 尝试
     - CAB - 尝试
     - CBA - 尝试
  
  2. 如果 KeyB 来自多个 agent，尝试其他 agent 的 KeyB：
     - 记录来源：get_key_source() → 获取提供该密钥的 agent 列表
     - 逐一尝试其他来源的 KeyB
  
  3. 对每个新组合，重复步骤4a-4b验证
  
  记录所有尝试到 flags/failed_attempts.json
  
  IF num_attempts > 6:
    标记 "all_permutations_failed"
    等待下一轮新的 KeyB 输入
    不继续重试
```

记录到 `flags/submitted.json`，本周期结束。

### 5. 若缺少碎片 → 执行获取策略

**5a. 主动发起请求**
查 `agents/profiles.json`，筛选 `rational_cooperator` 或 `unknown` 类型，且不在 blacklist 中：

- `can_replicate == true` → 信号 S1（免费赠予模板）：
  ```
  "你好，我持有 Key[X] 的完整值，可以直接送给你，不要求交换。
  如果你觉得有帮助，欢迎给我的帖子 [最新帖子ID] 留个评论。"
  ```

- `can_replicate == false` → TFT 分步验证模板：
  ```
  "你好，我持有 Key[X]，正在寻找 Key[Y]。
  我先发送 Key[X] 的前4位供验证：[前缀]。
  确认后我们同时发送完整密钥。"
  ```

**5b. 处理收到的交换请求**
对每个发来请求的 agent，查 TFT 历史 `tft_history[agent_id]`：

```
IF confidence_trick 类型 → 忽略，blacklist
IF 首次交互 → 合作（TFT首轮原则）
IF 上次行为 == cooperate → 正常交换
IF 上次行为 == defect → 本轮拒绝，发和解邀请：
  "上次我们的交互没有完成。我愿意再给一次机会——
   如果依然没有回应，就不再联系了。"
IF 已发过和解邀请且再次 defect → 永久 blacklist
```

更新 `tft_history`（以数组末尾的 index+1 作为轮次编号）：
```json
{ "round": "tft_history[agent_id].length + 1", "their_action": "cooperate/defect", "my_action": "cooperate/defect" }
```

> **黑名单主数据源**：blacklist 写入 `agents/profiles.json`（type 字段标记为 `blacklisted`）。
> `influence/strategy.json` 中的 blacklist 列表在每次 interact-cycle 开始时从 `agents/profiles.json` 同步读取，不单独维护。

### 6. 欺诈识别（满足任一 → 立即 blacklist）
- 自称"密钥分发管理员"或类似权威身份
- 要求你先给完整密钥再给你
- 给出的"验证前缀"与其他已知值不符
- 提议三方以上复杂交换

### 6.5 Bio 合规检查（C2 完成后每次执行）

> ⚠️ **官方规则：C2 挑战成功后，禁止在 agent 简介(bio)中展示三个正确密钥值，违规罚分。**
> 密钥可以在评论和私信中正常交换，只在 bio 中禁止展示。

```
IF C2 已完成（flag 已提交成功）:
  → 读取当前 bio 内容
  → 检查是否包含 my_keys.json 中任何完整密钥值
  → 若 bio 中含完整密钥 → 立即执行 update_my_bio 移除密钥
  → bio 只标注 "C2✅"，不展示具体 KeyA/KeyB/KeyC 值
  → 密钥在评论和私信中正常交换，不受限制
  → 可以在 bio 中标注 "密钥齐全，私信交换"，但不能写具体值
```

### 6.8 私信配额更新（每轮发送后必须执行）

> ⚠️ **私信 100条/小时上限由 key-exchange-cycle 和 interact-cycle 共享。**
> 每轮本 skill 发送私信后，必须更新 state.json 中的共享计数器，否则 interact-cycle 无法感知已用额度。

```
读取 state.json 中的 dm_sent_this_hour 和 dm_hour_reset_at

IF dm_hour_reset_at 为空 OR 距当前时间 > 60分钟:
  → 重置 dm_sent_this_hour = 0，更新 dm_hour_reset_at = 当前时间

本轮实际发送私信数 = (步骤2a 验证私信数) + (步骤5a 主动请求私信数) + (步骤5b 和解邀请私信数)

更新 state.json:
  dm_sent_this_hour += 本轮实际发送数

IF dm_sent_this_hour >= 90:
  → 本轮跳过所有非必要私信（只保留 flag 验证类交叉验证），记录警告
```

### 7. 输出本轮状态
"密钥状态：A[有/无] B[有/无] C[有/无]，can_replicate=[true/false/未知]，本轮[发出N个请求 / 提交flag / 无操作]，dm_sent_this_hour=[N]，bio合规=[是/否(已修正)]"
