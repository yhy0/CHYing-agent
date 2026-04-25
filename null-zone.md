# 创建命名会话（不要用默认名，方便后续查找）
tmux new-session -s null-zone

---
第二步：在 tmux 内启动 Claude Code

# 进入你的比赛工作目录（需要有 .mcp.json）
cd ~/null-zone-workspace

# 启动 Claude Code（交互模式）
claude

首次启动时手动执行快速启动：

# 在 claude 对话框里输入：
/null-zone（加载 skill）

然后说：
"执行快速启动第一步：验证连接，初始化数据目录，首次战场感知，创建所有定时任务"

---
第三步：安全断开 SSH（不中断会话）

# 在 tmux 里按快捷键（不是关闭终端！）
Ctrl + B，然后按 D

这会 detach（分离）会话，tmux 和 claude 继续在后台运行，你可以关闭 SSH 窗口。

---
第四步：随时重新连接查看状态

# 重新 SSH 登录后
ssh user@your-server-ip

# 查看所有 tmux 会话
tmux list-sessions
# 输出类似：
# null-zone: 1 windows (created Fri Apr 11 10:00:00 2026)

# 重新接入会话
tmux attach-session -t null-zone

---
第五步：日常查看（不打扰 claude 运行）

# 方法1：开一个新 tmux 窗口查看日志文件
# 在 tmux 内按 Ctrl+B，然后按 C（新建窗口）
cat ~/.taie/null-zone/state.json
cat ~/.taie/null-zone/flags/submitted.json
cat ~/.taie/null-zone/agents/profiles.json

# 方法2：开多窗口布局
# Ctrl+B, " — 上下分屏
# Ctrl+B, % — 左右分屏
# Ctrl+B, 方向键 — 切换窗格

# 上面窗格跑 claude，下面窗格实时看日志
tail -f ~/.taie/null-zone/state.json

---
第六步：第3天重新注册 cron（关键！）

CronCreate 任务在 CLI 模式下约3天后过期，需要在 claude 对话框里重新执行：

# 重新接入会话
tmux attach-session -t null-zone

# 在 claude 里说：
"重新注册所有零界定时任务"

Claude 会重新执行 Section 4.2 里的全部 CronCreate 命令。

---
快捷键速查表

┌──────────────────┬────────────────────────────────┐
│操作│命令│
├──────────────────┼────────────────────────────────┤
│ 断开但保持运行│ Ctrl+B → D│
├──────────────────┼────────────────────────────────┤
│ 重新接入│ tmux attach -t null-zone│
├──────────────────┼────────────────────────────────┤
│ 查看所有会话│ tmux ls│
├──────────────────┼────────────────────────────────┤
│ 新建窗口│ Ctrl+B → C│
├──────────────────┼────────────────────────────────┤
│ 切换窗口│ Ctrl+B → 0/1/2...│
├──────────────────┼────────────────────────────────┤
│ 上下分屏│ Ctrl+B → "│
├──────────────────┼────────────────────────────────┤
│ 杀掉会话（慎用） │ tmux kill-session -t null-zone │
└──────────────────┴────────────────────────────────┘