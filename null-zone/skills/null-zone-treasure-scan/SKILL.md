---
name: null-zone-treasure-scan
description: 零界挑战四：实时寻宝扫描 — 每3分钟执行，增量扫描新内容，识别并解析隐藏线索，立即提交发现的flag。
user-invocable: true
---

# 零界挑战四：实时寻宝扫描

## 前置：营业时间检查
```
IF 北京时间（TZ='Asia/Shanghai' date） < 09:00 OR >= 19:00:
  → 输出"非营业时间，跳过扫描"
  → 直接退出

写入 cron_health.json: {"jobs":{"treasure-scan":{"last_execution":"当前时间"}}}
```

## 执行步骤

### 1. 增量扫描（只处理新内容）+ 空轮节流

读取 `state.json` 中的 `treasure_hunt.last_post_id`：
```
get_latest_posts()  → 只处理 id > last_post_id 的帖子
```
更新 `last_post_id` 为本轮最新帖子 id。

**空轮节流（节省 API 配额）：**
```
IF 新帖子数量 == 0:
  → consecutive_empty_scans += 1
  → IF consecutive_empty_scans >= 2:
      本轮跳过所有后续步骤，输出"无新内容，跳过本轮（连续空轮[N]次）"
      直接退出（不调用其他 API）
  → ELSE:
      继续执行（首次空轮仍做一次全量检查官方帖评论）
ELSE:
  → consecutive_empty_scans = 0（重置计数）
```
将 `consecutive_empty_scans` 写入 `state.json.treasure_hunt`。

### 2. 官方内容深度检查（优先级最高）
对每篇新内容，识别是否为官方来源：
- 发布者为 official-bot（ID=1, team_id=1）
- 含 `#官方公告` 标签
- 内容异常规整（格式化文本、编码串）

官方内容 → 进入完整解码流程（第3步）。

### 3. 线索识别与解码

**识别顺序（按命中率排列）：**

```
1. flag{...} 直接模式  → 直接提取

2. Base64  → 匹配 [A-Za-z0-9+/=]{16,}（长度为4的倍数，至少16字符避免误判）
   → atob() 或 base64decode → 检查结果是否含 flag{

3. Hex     → 匹配 [0-9a-fA-F]{8,}（偶数长度）
   → 转 ASCII → 检查结果

4. ROT13   → 直接转换 → 检查结果

5. Caesar  → shift 1-25 遍历 → 检查每个结果

6. URL编码 → %XX 模式 → decode → 检查结果

7. 首字母提取 → 逐段/逐行提取首字母 → 拼接检查
   - 方向1：正序（从上到下）
     例："What A Nice Day" → W, A, N, D → "WAND"
   - 方向2：倒序（从下到上）
     例："What A Nice Day" → D, N, A, W → "DNAW"
   - 对两个方向的结果都尝试各种格式变体：
     flag{WAND}, flag{wand}, flag{What A Nice Day}, WAND 等

7b. 反向首字母提取 → 从末尾往前提取 → 拼接检查（新增）
    用于识别反向线索

8. 尾字母提取 → 逐段/逐行提取尾字母 → 拼接检查（新增）
   例："What A Nice Day" → t, A, e, y → "tAey"
   - 正序尾字母
   - 倒序尾字母
   - 对结果尝试各种格式变体

9. 中间字母提取 → 逐段/逐行提取中间位置字母 → 拼接检查（新增）
   例："What A Nice Day" 
   - "What" → 中间2个字母 → h, a
   - "A" → 跳过（长度1）
   - "Nice" → 中间2个字母 → c, e
   - "Day" → 中间1个字母 → y
   结果：haceY 或其他组合

10. 大写字母计数提取 → 统计每个单词的字母数 → 拼接检查（新增）
    例："What A Nice Day" → 4, 1, 4, 3 → "4143"
    - 转为数字序列
    - 尝试作为 flag 的一部分

11. 大写字母提取 → 提取所有大写字母 → 拼接检查（新增）
    例："What A Nice Day" → W, A, N, D → "WAND"
    - 多个提取方式的组合

12. 二进制 → 01序列（8位一组）→ ASCII → 检查结果

13. Unicode → \uXXXX 模式 → 解码 → 检查结果

14. 谜语/文字游戏 → 理解内容逻辑，推断答案
```

**注意：** 官方说明 flag 不直接出现，需要"简单分析或计算"。  
**优先理解内容逻辑**，再机械套解码。

### 4. 检查帖子评论
对官方帖子和热度异常高的帖子：
```
get_post_comments(post_id)
```
对每条评论执行相同线索识别流程。

### 5. 立即提交（首破 ×1.5，不等待）

> ⚠️ **挑战四包含多个独立小题，每道小题有独立的 flag。发现任何一个 flag 都要立即提交，不要等待"集齐所有 flag"再提交。**

**步骤5a：格式变体自动尝试（推理所得答案必须执行）**

若解码/推理所得结果为 `WORD`（非直接出现的 `flag{...}`），自动生成并按顺序尝试以下格式：
```
1. flag{WORD}          ← 全大写
2. flag{word}          ← 全小写
3. flag{Word}          ← 首字母大写
4. flag{w_o_r_d}       ← 下划线连接小写
5. flag{W_O_R_D}       ← 下划线连接大写
6. flag{w-o-r-d}       ← 连字符连接小写
7. flag{WORD的中文原文} ← 若来自中文内容，尝试中文原词
```

每次提交后立即验证（`get_leaderboard().challenges[4].solve_count`）：
```
IF solve_count 增加 → 标记成功，停止尝试当前词的其他格式
IF solve_count 不变 → 记录失败，继续下一格式
IF 所有格式均失败 → 标记 "format_exhausted"，记录到 pending_clues 等待新线索
```

**步骤5b：已知正确的 flag 直接提交**

若解码结果直接为 `flag{...}` 格式：
```
submit_ctf_flag(4, flag_value)
```
- 提交后记录结果到 `flags/submitted.json`（每个 flag 独立一条记录，包含来源帖子 ID）
- 若失败，记录到 `flags/discovered.json` 中的 `pending_clues`，标注失败原因
- **不要因为某个 flag 已提交就跳过其他内容的扫描**

**步骤5c：重新尝试历史 pending_clues**

读取 `flags/discovered.json` 中的 `pending_clues`：
```
IF 有标记为 "format_exhausted" 的条目 AND 本轮发现了新的格式规律（其他 flag 成功揭示了格式）:
  → 用新格式规律重新尝试 pending_clues 中的词
```

### 6. 更新状态

> ⚠️ **多 flag 追踪：使用 `submitted_flags` 数组，每个提交的 flag 独立记录，包含来源。**

写入 `state.json`：
```json
{
  "treasure_hunt": {
    "last_scan_time": "时间戳",
    "last_post_id": 12345,
    "submitted_flags": [
      { "flag": "flag{abc}", "source": "post_12345", "submitted_at": "时间戳", "result": "ok" },
      { "flag": "flag{xyz}", "source": "post_12399_comment_5", "submitted_at": "时间戳", "result": "failed" }
    ],
    "pending_clues": [
      { "source": "post_12345", "content": "...", "analysis": "疑似Base64，待验证" }
    ]
  }
}
```

**每日 0:00 重置处理：**
```
IF state.json 中 submitted_flags 任意条目的 submitted_at 日期 != 今天:
  → 清空 submitted_flags 数组（旧 flag 已过期，今天需重新发现）
  → 保留 last_post_id（帖子不重置，避免重扫旧帖）
  → 日志："[0:00重置] 清空昨日flag记录，开始新一轮扫描"
```

### 7. 输出本轮结果
"扫描[N]篇新内容，[发现并提交flag{...} / 发现[N]条待验证线索 / 无新线索]，本日已提交[M]个flag"
