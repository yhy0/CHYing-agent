"""Token 用量追踪与格式化工具

从 base.py 提取的 token 相关功能：
- _get_context_window_size: 获取模型上下文窗口大小
- _StreamUsageTracker: 从 StreamEvent 中实时解析并累积 token 用量
- _log_usage_summary: 输出醒目的 token 用量摘要
- 格式化辅助函数
"""

import os
import logging
from typing import Dict, Any, Optional

from ..common import log_system_event

# 模块级 logger
_logger = logging.getLogger(__name__)


def _get_context_window_size() -> int:
    """获取模型上下文窗口大小（tokens），用于计算 ctx 百分比。

    读取 CLAUDE_CODE_AUTO_COMPACT_WINDOW，与 CLI compact 阈值使用同一分母。
    未设置时回退到 200000（CLI 的 MODEL_CONTEXT_WINDOW_DEFAULT）。
    """
    raw = os.environ.get("CLAUDE_CODE_AUTO_COMPACT_WINDOW", "")
    if raw.strip():
        try:
            return int(raw.strip())
        except ValueError:
            pass
    return 200_000


# ==================== Token 用量日志辅助函数 ====================

# Token 摘要颜色：粗体青绿色（与 common.py 中 _LLM_OUTPUT_STYLES["Token Usage"] 一致）
_TOKEN_STYLE = "\033[1;38;2;80;220;180m"
_TOKEN_RESET = "\033[0m"


def _colorize_token_text(text: str) -> str:
    """对 token 摘要文本着色（仅终端模式下生效）"""
    import sys
    if not sys.stdout.isatty():
        return text
    return f"{_TOKEN_STYLE}{text}{_TOKEN_RESET}"


def _format_token_count(n: int) -> str:
    """格式化 token 数量为可读字符串（如 125.3K）"""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    elif n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def _make_progress_bar(pct: float, width: int = 20) -> str:
    """生成文本进度条"""
    filled = int(width * min(pct, 100) / 100)
    return "█" * filled + "░" * (width - filled)


def _estimate_cost_from_tokens(input_tokens: int, output_tokens: int) -> float:
    """从 token 数量估算 cost（美元）。

    当 ResultMessage 未到达（cancel/timeout）时，用 stream tracker 已收集的
    token 数据做粗略估算，避免 cost 丢失为 0。

    使用保守的通用费率：input $3/M, output $15/M（接近 Claude Sonnet 定价）。
    实际模型可能更便宜或更贵，但估算总比 $0 好。
    """
    INPUT_RATE = 3.0 / 1_000_000   # $/token
    OUTPUT_RATE = 15.0 / 1_000_000  # $/token
    return input_tokens * INPUT_RATE + output_tokens * OUTPUT_RATE


class _StreamUsageTracker:
    """从 StreamEvent 中实时解析并累积 token 用量。

    Claude SDK 的 StreamEvent.event 是原始 Anthropic API 流式事件透传：
    - message_start: event["message"]["usage"]["input_tokens"]
    - message_delta:  event["usage"]["output_tokens"]

    每个 API message（一个 assistant turn）会有一对 message_start + message_delta。
    在一次 query() 中，agent 可能经历多个 API turns（工具调用循环），
    所以 input_tokens 会随着上下文增长而递增，output_tokens 累加。
    """

    def __init__(self, baseline_input_tokens: int = 0) -> None:
        # 最新一次 message_start 中的 input_tokens（反映当前上下文大小）
        # 如果 stream event 不提供，则用 baseline 估算
        self.latest_input_tokens: int = 0
        # 上一次 ResultMessage 提供的 input_tokens，作为本轮的基线估算
        self._baseline_input_tokens: int = baseline_input_tokens
        # 累积的 output_tokens（所有 turns 合计）
        self.cumulative_output_tokens: int = 0
        # 当前 turn 的 output_tokens（单次 message_delta）
        self._current_turn_output: int = 0
        # 是否收到过有效的 token 数据
        self.has_data: bool = False
        # API turn 计数
        self.api_turns: int = 0
        # 是否已记录过缺少 input_tokens 的警告（避免刷屏）
        self._logged_missing_input: bool = False

    def process_event(self, event: Dict[str, Any]) -> None:
        """处理一个 StreamEvent.event 字典，提取 token 数据"""
        event_type = event.get("type")
        if event_type == "message_start":
            msg = event.get("message", {})
            usage = msg.get("usage", {})
            input_tok = usage.get("input_tokens")
            if input_tok is not None:
                self.latest_input_tokens = input_tok
                self.has_data = True
                self.api_turns += 1
                self._current_turn_output = 0
            else:
                # input_tokens 不在标准位置，尝试 prompt_tokens（OpenAI 兼容格式）
                alt_usage = event.get("usage", {})
                alt_input = alt_usage.get("input_tokens") or alt_usage.get("prompt_tokens")
                if alt_input is not None:
                    self.latest_input_tokens = alt_input
                    self.has_data = True
                    self.api_turns += 1
                    self._current_turn_output = 0
                else:
                    # 仍然计数 turn，只是没有 input_tokens 数据
                    self.api_turns += 1
                    self._current_turn_output = 0
                    if not self._logged_missing_input:
                        self._logged_missing_input = True
                        log_system_event(
                            f"[TokenTracker] message_start missing input_tokens",
                            {"event_keys": list(event.keys()), "message_keys": list(msg.keys()), "usage": usage},
                        )
        elif event_type == "message_delta":
            usage = event.get("usage", {})
            output_tok = usage.get("output_tokens") or usage.get("completion_tokens")
            if output_tok is not None:
                self._current_turn_output = output_tok
                self.cumulative_output_tokens += output_tok
                self.has_data = True

    def format_inline(self) -> str:
        """生成紧凑的 inline token 摘要（用于工具调用日志后附带），带颜色高亮"""
        if not self.has_data:
            return ""
        parts = []
        # 优先使用 stream event 提供的 input_tokens，否则用 baseline + 累积 output 估算
        effective_input = self.latest_input_tokens
        if effective_input == 0 and self._baseline_input_tokens > 0:
            # 估算：上次 query 结束时的 input_tokens + 本轮累积的 output_tokens
            # （上下文 = 上次的上下文 + 新增的 output，近似值）
            effective_input = self._baseline_input_tokens + self.cumulative_output_tokens
            estimated = True
        else:
            estimated = False
        if effective_input > 0:
            ctx_pct = effective_input / _get_context_window_size() * 100
            est_mark = "~" if estimated else ""
            parts.append(f"ctx={est_mark}{_format_token_count(effective_input)}({ctx_pct:.0f}%)")
        parts.append(f"out={_format_token_count(self.cumulative_output_tokens)}")
        parts.append(f"turns={self.api_turns}")
        return _colorize_token_text(" ".join(parts))


def _log_usage_summary(
    agent_type: str,
    usage: Optional[Dict[str, Any]],
    total_cost_usd: Optional[float],
    latest_context_tokens: int = 0,
    prev_input_tokens: int = 0,
    prev_cost_usd: float = 0.0,
) -> None:
    """输出醒目的 token 用量摘要（最终 ResultMessage 时调用）

    Args:
        usage: ResultMessage.usage（累计值：session 生命周期内的总 input/output tokens）
        total_cost_usd: 总费用（SDK session 级累计）
        latest_context_tokens: 最后一次 API turn 的实际上下文大小（来自 StreamEvent 的 message_start）
        prev_input_tokens: 上一次 ResultMessage 的 cumulative input_tokens，用于计算 per-turn 增量
        prev_cost_usd: 上一次 ResultMessage 的 cumulative cost，用于计算 per-turn 增量
    """
    if not usage and total_cost_usd is None:
        return

    input_tok = usage.get("input_tokens", 0) if usage else 0
    output_tok = usage.get("output_tokens", 0) if usage else 0
    total_tok = input_tok + output_tok

    # Per-turn 增量（当前 SDK 累计值 - 上一次 SDK 累计值）
    # prev == 0 表示首轮，此时 delta 就是 input_tok 本身
    delta_input = input_tok - prev_input_tokens if input_tok >= prev_input_tokens else 0
    delta_cost = (total_cost_usd - prev_cost_usd) if total_cost_usd is not None and total_cost_usd >= prev_cost_usd else 0.0

    cost_str = f"${total_cost_usd:.2f}(+${delta_cost:.2f})" if total_cost_usd is not None else "N/A"

    # 上下文大小：优先使用 stream event 提供的最后一次 API turn 的 input_tokens（真实上下文大小）
    # ResultMessage.usage["input_tokens"] 是 session 级别的累计值，不能用于上下文百分比计算
    ctx_tokens = latest_context_tokens if latest_context_tokens > 0 else 0
    ctx_window = _get_context_window_size()
    ctx_pct = (ctx_tokens / ctx_window * 100) if ctx_tokens else 0
    ctx_bar = _make_progress_bar(ctx_pct)

    summary = _colorize_token_text(
        f"Token Usage: "
        f"input={_format_token_count(input_tok)}(+{_format_token_count(delta_input)}) "
        f"output={_format_token_count(output_tok)} "
        f"total={_format_token_count(total_tok)} | "
        f"Context: {ctx_bar} {ctx_pct:.1f}% | "
        f"Cost: {cost_str}"
    )
    log_system_event(f"[{agent_type}] {summary}")
