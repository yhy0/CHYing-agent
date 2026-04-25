#!/usr/bin/env bash

######################################
# tmux new-session -s cy
# cd /home/ubuntu/CHYing-agent
# ./run_tencent_ctf_delayed.sh
# tmux attach -t cy
# tmux ls
######################################


PROJECT_DIR="/home/ubuntu/CHYing-agent"
cd "$PROJECT_DIR"

# 延迟 10 分钟启动, 8:50 不能忘记运行，否则会错过比赛
sleep $((60))

while true; do
    nohup uv run run_tencent_ctf.py --priority-level 3 "$@" >/dev/null 2>&1 &
    PID=$!

    echo "[OK] 已启动 run_tencent_ctf.py，PID: $PID"

    while kill -0 "$PID" 2>/dev/null; do
        sleep $((5 * 60))
    done

    echo "[WARN] 检测到进程退出，5 秒后自动重启"
    sleep 5
done
