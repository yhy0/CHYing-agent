"""
停滞检测与 Guidance 支持模块
===========================

提供 Agent 停滞检测和跨会话知识提取：
- ReflectionTracker: 四层停滞检测状态机 + SOFT_WARN
- Dead Ends / 攻击向量提取（供 Guidance Loop 和 PreToolUse ABANDON 使用）
- 会话摘要持久化与历史管理

从 base.py 拆分而来，被 BaseClaudeAgent.query() 和 Hook 系统引用。
"""

import asyncio
import json
import logging
import re as _re_module
from collections import Counter
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any

# ── 控制平面：操作分类正则 ───────────────────────────────────
_RE_PATH_SCAN = _re_module.compile(
    r"\b(curl|wget|ffuf|gobuster|dirsearch|feroxbuster|dirb|nikto)\b", _re_module.I
)
_RE_API_VARIANT = _re_module.compile(
    r"\bcurl\b.*\b(POST|PUT|PATCH)\b.*(-d|--data|--json)", _re_module.I | _re_module.S
)
_RE_CREDENTIAL_GUESS = _re_module.compile(
    r"\b(hydra|medusa|john|hashcat|crackmapexec|brute|login|auth)\b", _re_module.I
)
_RE_CONFIG_QUERY = _re_module.compile(
    r"\?(versioning|logging|tagging|encryption|acl|policy|lifecycle|cors|website)\b",
    _re_module.I,
)
_RE_S3_ENUM = _re_module.compile(
    r"\b(aws\s+s3|s3api|s3\.amazonaws\.com)\b", _re_module.I
)
_RE_PORT_SCAN = _re_module.compile(r"\b(nmap|masscan)\b", _re_module.I)
_RE_URL_HOST = _re_module.compile(r'https?://([^/\s:"\']+)')
_RE_URL_PATH = _re_module.compile(r'https?://[^/\s]+(\/[^\s"\']*)')

# L2 硬阻断只对高重复/低副作用/低语义依赖的 class 启用
_L2_ENABLED_CLASSES = frozenset({"path_scan", "config_read", "s3_enum"})
_L1_THRESHOLD = 3
_L2_THRESHOLD = 5
_CHECKPOINT_INTERVAL = 15

_logger = logging.getLogger(__name__)


class ReflectionAction(Enum):
    """反思检测结果：无操作 / 软警告（additionalContext 注入）/ 硬反思（interrupt + 反思 agent）"""

    NONE = "none"
    SOFT_WARN = "soft_warn"
    HARD_REFLECT = "hard_reflect"


# ---------------------------------------------------------------------------
# 数据源访问
# ---------------------------------------------------------------------------


def get_current_log_file_path() -> str:
    """从当前题目的 challenge_logger 提取日志文件绝对路径"""
    from ..common import get_current_challenge_logger

    challenge_logger = get_current_challenge_logger()
    if challenge_logger and challenge_logger.handlers:
        handler = challenge_logger.handlers[0]
        if hasattr(handler, "baseFilename"):
            return handler.baseFilename
    return "(日志路径未知)"


def get_current_memory_path() -> Optional[str]:
    """返回当前题目的 findings.log 路径（如果存在）"""
    try:
        from ..runtime.context import get_current_work_dir

        work_dir = get_current_work_dir()
        if work_dir:
            memory_file = work_dir / "findings.log"
            if memory_file.exists():
                return str(memory_file)
    except Exception:
        pass
    return None


def get_current_work_dir_str() -> Optional[str]:
    """返回当前题目工作目录路径字符串（如果存在）"""
    try:
        from ..runtime.context import get_current_work_dir

        work_dir = get_current_work_dir()
        if work_dir and work_dir.exists():
            return str(work_dir)
    except Exception:
        pass
    return None


def persist_session_summary(report: str, reflection_count: int) -> None:
    """将会话摘要追加写入 dumps/ 目录。

    写入 {work_dir}/dumps/reflection_history.md，追加模式。
    供新会话和 compact 指令参考。
    """
    try:
        from ..runtime.context import get_current_work_dir

        work_dir = get_current_work_dir()
        if not work_dir:
            _logger.warning("无 work_dir，跳过反思报告持久化")
            return

        dumps_dir = work_dir / "dumps"
        dumps_dir.mkdir(parents=True, exist_ok=True)
        history_file = dumps_dir / "reflection_history.md"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"## Reflection #{reflection_count} -- {timestamp}\n\n{report}\n\n---\n\n"

        with open(history_file, "a", encoding="utf-8") as f:
            f.write(entry)

        _logger.info(f"反思报告已持久化: {history_file}")
    except Exception as e:
        _logger.warning(f"反思报告持久化失败: {e}")


def read_reflection_history() -> Optional[str]:
    """读取已持久化的历史反思文件（最近 2 条）。

    只返回最近 2 条反思记录，避免过多历史挤占 haiku agent 的上下文窗口。

    Returns:
        最近的历史反思内容，或 None（如果不存在或读取失败）
    """
    try:
        from ..runtime.context import get_current_work_dir

        work_dir = get_current_work_dir()
        if not work_dir:
            return None

        history_file = work_dir / "dumps" / "reflection_history.md"
        if history_file.exists():
            content = history_file.read_text(encoding="utf-8")
            entries = [e.strip() for e in content.split("\n---\n") if e.strip()]
            if len(entries) > 2:
                entries = entries[-2:]
            return "\n\n---\n\n".join(entries)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Dead Ends / 攻击向量提取（供 Guidance Loop 和 ABANDON 使用）
# ---------------------------------------------------------------------------


def extract_dead_ends(work_dir: Path) -> list[str]:
    """从 progress.md Dead Ends 段 + findings.log 中提取已确认的失败方向列表。

    只提取经过实际验证的 dead_end（标记为 VERIFIED-BY-EXECUTION 或 OBSERVED）。
    未验证的推断（UNVERIFIED-INFERENCE）不加入禁止列表，避免误导新 agent。

    Returns:
        禁止列表（每条是一个失败方向的简要描述）
    """
    import re

    dead_ends: list[str] = []

    progress_file = work_dir / "progress.md"
    if progress_file.exists():
        try:
            content = progress_file.read_text(encoding="utf-8")
            match = re.search(
                r"## Dead Ends.*?\n\n(.*?)(?=\n## |\Z)",
                content,
                re.DOTALL,
            )
            if match:
                section = match.group(1).strip()
                if not section.startswith("(auto-updated"):
                    for line in section.split("\n"):
                        line = line.strip()
                        if line.startswith("- "):
                            dead_ends.append(line[2:])
        except Exception:
            pass

    findings_file = work_dir / "findings.log"
    if findings_file.exists():
        try:
            content = findings_file.read_text(encoding="utf-8")
            # 按 finding 块分割（以 ### 开头的标题行）
            blocks = re.split(r"(?=^### )", content, flags=re.MULTILINE)
            for block in blocks:
                block = block.strip()
                if not block:
                    continue
                # 只处理 dead_end 类型的 finding
                if "[dead_end]" not in block.lower():
                    continue
                # 只信任经过实际验证的 dead_end
                if "UNVERIFIED-INFERENCE" in block:
                    continue
                # 提取标题
                title_match = re.match(
                    r"###\s+\S+\s+\[dead_end\]\s+(.+?)(?:\s+\[.+\])?\s*$",
                    block.split("\n")[0],
                    re.IGNORECASE,
                )
                if title_match:
                    title = title_match.group(1).strip()
                    if title and title not in dead_ends:
                        dead_ends.append(title)
        except Exception:
            pass

    return dead_ends


def extract_prior_findings(work_dir: Path) -> list[str]:
    """从 progress.md Attack Tree + findings.log 提取有效发现列表。

    Returns:
        有效发现列表（每条是一个关键发现的简要描述）
    """
    import re

    findings: list[str] = []

    progress_file = work_dir / "progress.md"
    if progress_file.exists():
        try:
            content = progress_file.read_text(encoding="utf-8")
            match = re.search(
                r"## Attack Tree\n\n(.*?)(?=\n## |\Z)",
                content,
                re.DOTALL,
            )
            if match:
                section = match.group(1).strip()
                if not section.startswith("(auto-updated"):
                    for line in section.split("\n"):
                        line = line.strip()
                        if line.startswith("- "):
                            findings.append(line[2:])
        except Exception:
            pass

    return findings


# ---------------------------------------------------------------------------
# ReflectionTracker — 停滞检测状态机
# ---------------------------------------------------------------------------


class ReflectionTracker:
    """追踪 Agent 停滞状态，触发反思。

    四层检测机制：
    1. 连续失败检测：连续 N 次工具调用返回错误
    2. 无进展检测：连续 N 次调用无正面发现（record_key_finding 的正面 kind）
    3. 重复模式检测：短窗口内重复执行语义相似的操作（同工具+相似参数）
    4. 无效操作检测：操作成功但输出含 Permission denied 等失败信号

    支持 pending 反思机制：反思提示先暂存，延迟到合适时机（子代理返回后或
    累积 N 次工具调用后）再投递给 Orchestrator，避免误投递给子代理。
    """

    # record_key_finding 中被视为「正面进展」的 kind（只有这些才重置无进展计数器）
    _POSITIVE_FINDING_KINDS = frozenset(
        {
            "vulnerability",
            "credential",
            "flag",
            "artifact",
            "exploit",
        }
    )
    # 额外的正面信号词（不是 kind，但出现在输出中表示有实质发现）
    _POSITIVE_EXTRA_SIGNALS = frozenset(
        {
            "found",
            "discovered",
        }
    )
    # 部分正面 kind：重置 no_progress 和 ineffective 计数器（给予新窗口），
    # 但不取消已发起的软警告状态（_soft_warning_sent 保持不变）。
    # 避免 agent 通过频繁记录低价值 info 来无限拖延反思。
    _PARTIAL_POSITIVE_KINDS = frozenset(
        {
            "info",
            "config",
            "note",
        }
    )

    # 工具输出中表示「目标环境阻挡操作」的信号关键词（全部小写，匹配时 case-insensitive）。
    # 仅包含权限/访问/连接类错误——表明 agent 的操作方向被环境阻止。
    # 不包含环境能力探测类错误（command not found, no such file）——
    # 这些只表明工具不可用或路径不存在，agent 会自行切换方案，不代表停滞。
    _INEFFECTIVE_SIGNALS = (
        "permission denied",
        "access denied",
        "operation not permitted",
        "connection refused",
        "connection timed out",
        "authentication failed",
        "unauthorized",
        "403 forbidden",
    )

    def __init__(
        self,
        consecutive_failure_threshold: int = 5,
        no_progress_threshold: int = 50,
        repetition_threshold: int = 8,
        ineffective_threshold: int = 15,
        max_reflections: int = 5,
        pattern_window_size: int = 12,
        early_phase_immunity: int = 50,
    ):
        self.consecutive_failure_threshold = consecutive_failure_threshold
        self.no_progress_threshold = no_progress_threshold
        self.repetition_threshold = repetition_threshold
        self.ineffective_threshold = ineffective_threshold
        self.max_reflections = max_reflections
        self.pattern_window_size = pattern_window_size
        # 早期豁免：前 N 次非 UI 工具调用内不触发任何反思（计数器正常累积）。
        # 给 agent 充足的探索空间，避免在侦察/尝试阶段被过早打断。
        self.early_phase_immunity = early_phase_immunity
        self._consecutive_failures = 0
        self._total_calls_since_finding = 0
        self._ineffective_count = 0  # 成功但无效的操作计数
        # 早期豁免计数器：追踪非 UI 工具调用总数，前 early_phase_immunity 次内不触发反思
        self._total_non_ui_calls = 0
        self._reflection_count = 0
        # 工具调用模式追踪：记录最近 N 次调用的 (工具名, 参数摘要) 用于重复检测
        self._call_history: list[str] = []
        # 最近一次反思报告（供 compact 指令和日志使用）
        self._last_reflection_report: Optional[str] = None
        # 两阶段反思：是否已发送过软警告（首次 → 软警告，第二次 → 硬反思）
        self._soft_warning_sent = False
        # 最近一次触发原因（在计数器重置前记录，供 build_soft_warning_text 使用）
        self._last_trigger_reasons: list[str] = []
        # Post-reflection todo 执行提醒：硬反思后的前 N 次工具调用持续提醒 agent 按 todo 执行
        self._post_reflection_reminder_countdown = 0
        # 攻击链综合提醒：每 N 次非 UI 工具调用提醒 agent 综合已发现信息
        self._synthesis_interval = 25
        self._calls_since_last_synthesis = 0
        # progress.md 更新提醒：每 N 次非 UI 工具调用提醒 agent 更新 progress.md
        self._progress_interval = 40
        self._calls_since_last_progress_reminder = 0
        # Skill hints 注入：统计所有工具调用（含 UI 工具），间隔更长
        self._skill_hint_interval = 50
        self._calls_since_last_skill_hint = 0
        # on_tool_result 判断后的结果标志：供 hook 后续逻辑（reminder 等）判断
        # 是否应将本次 evaluate_script 视为非 UI 工具
        self._last_result_was_terminal_eval = False
        # 冷启动标志：首轮 fresh start 时为 True，compact/reflection/continuation 后变 False。
        # 用于 PreToolUse hook 拦截冷启动阶段的 progress.md 读取。
        self._is_cold_start = True
        # ABANDON 强制执行标志：由 Guidance Loop 在检测到绕圈时启用。
        # 启用后 PreToolUse hook 会匹配 Dead Ends 列表，阻止 agent 走旧路。
        self._abandon_active = False
        # Compact 恢复拦截计数器：由 base.py 在收到 compacting SystemMessage 时设为 >0，
        # PreToolUse hook 每次拦截递减，归零后停止拦截。
        self._compact_deny_remaining = 0
        # Compact 后已成功读取的主恢复文件集合：仅统计成功的 Read 调用。
        # 当集合包含当前要求的全部恢复文件（progress/findings/可选 hint）时，
        # 退出恢复模式（_compact_deny_remaining 清零）。
        self._compact_confirmed_reads: set = set()
        # ProgressCompiler 异步任务句柄：compact 开始时异步启动，recovery hook 消费。
        # compact 与 CLI LLM 摘要并行运行，产出 compact_handoff.md 供快速恢复。
        self._progress_compiler_task: Optional["asyncio.Task"] = None

        # ── Control Plane Phase 1 ────────────────────────────────
        # Same-class streak: bucket(class, host, surface_key) → 连续无 finding 调用数
        self._class_streak: Dict[tuple, int] = {}
        # 已触发过 L1 软提醒的 bucket（stagnation-recovery 仅清零这些）
        self._reminded_buckets: set = set()
        # 最近被递增的非 other bucket（_apply_finding_reset 用它定位要重置的 bucket）
        self._last_non_other_bucket: Optional[tuple] = None
        # Auto checkpoint
        self._checkpoint_buffer: list = []
        self._checkpoint_count: int = 0
        self._calls_since_checkpoint: int = 0
        # Hint 提醒计数（上限 2）
        self._hint_remind_count: int = 0
        self._hint_first_remind_at: int = 0  # 首次 hint 提醒时的 _total_non_ui_calls

        # ── Control Plane Phase 2 ────────────────────────────────
        # Unconsumed anomaly lifecycle
        self._anomaly_remind_count: Dict[str, int] = {}   # title → 提醒次数（上限 2）
        self._anomaly_last_status: Dict[str, str] = {}    # title → 上次看到的 status
        # 子代理 YAML 摘要（PostToolUse 存入，guidance query 一次性消费）
        self._last_subagent_yaml: Optional[dict] = None
        # Finding 提醒（25 次无 record_key_finding，一次性）
        self._finding_reminder_sent: bool = False

        # ── Phase 3: 评估指标采集 ────────────────────────────────
        self._metrics_l2_deny_count: int = 0
        self._metrics_l1_warn_count: int = 0
        self._metrics_soft_warn_count: int = 0
        self._metrics_yaml_parse_ok: int = 0
        self._metrics_yaml_parse_fail: int = 0
        self._metrics_finding_unlock_after_l2: int = 0
        self._metrics_abandon_block_count: int = 0
        self._metrics_first_finding_at: Optional[int] = None  # _total_non_ui_calls
        self._metrics_view_hint_count: int = 0
        self._metrics_stop_reasons: list = []
        self._metrics_finding_count: int = 0  # 所有 positive finding 计数

    def mark_warm(self) -> None:
        """标记会话已进入恢复态（compact/reflection/continuation 后），允许读取 progress.md。"""
        self._is_cold_start = False

    @property
    def is_cold_start(self) -> bool:
        return self._is_cold_start

    @staticmethod
    def _make_call_signature(
        tool_name: str, tool_input: Optional[dict] = None
    ) -> str:
        """从工具名和输入生成调用签名，用于重复模式检测。

        提取工具名和输入中的关键特征（命令模式、路径模式），忽略具体参数差异。
        例如多次 evaluate_script 执行 `ln -s ... /tmp/xxx` 会生成相似签名。

        注意：签名只提取操作语义（命令动词 + URL 路径），不包含 IP/域名。
        这样同一目标换不同路径/参数的新攻击不会被误拦。
        """
        import re

        # 标准化工具名
        short_name = (
            tool_name.split("__")[-1] if "__" in tool_name else tool_name
        )

        if not tool_input:
            return short_name

        # 提取输入中的关键模式
        input_str = (
            json.dumps(tool_input, ensure_ascii=False)
            if isinstance(tool_input, dict)
            else str(tool_input)
        )

        # 提取命令动词模式（ln -s, cat, grep, curl, symlink 等关键操作）
        cmd_patterns = re.findall(
            r"\b(ln\s+-[sf]+|symlink|curl\s|wget\s|chmod\s|cat\s|grep\s|terraform\s\w+|"
            r"nmap\s|sqlmap\s|gobuster\s|ffuf\s|find\s|mkdir\s|rm\s+-[rf]+)\b",
            input_str,
        )
        # 提取 URL 路径部分（不含 IP/域名，只保留路径），避免同目标不同路径被误拦
        # 例如 http://10.0.1.1/api/v1/login → /api/v1/login
        url_paths = re.findall(r"https?://[^/\s]+(/[^\s\"']+)", input_str)

        signature_parts = [short_name]
        if cmd_patterns:
            signature_parts.append("|".join(sorted(set(cmd_patterns))))
        if url_paths:
            # 只保留前 2 个唯一 URL 路径
            unique_paths = sorted(set(url_paths))[:2]
            signature_parts.append("|".join(unique_paths))

        return "::".join(signature_parts)

    def _check_repetition(self) -> bool:
        """检查最近的调用历史是否存在重复模式。

        在滑动窗口内，如果同一签名出现次数 >= repetition_threshold，
        说明 Agent 在做换汤不换药的重复操作。
        """
        if len(self._call_history) < self.repetition_threshold:
            return False

        window = self._call_history[-self.pattern_window_size :]
        counts = Counter(window)
        return any(c >= self.repetition_threshold for c in counts.values())

    # 浏览器 UI 交互/观察工具：不参与重复模式检测和 no_progress 计数。
    # 这些是正常页面导航和信息获取操作，天然高频（snapshot → click → fill → snapshot），
    # 不代表 Agent 陷入循环。攻击效果由 record_key_finding 衡量。
    #
    # type_text / press_key / evaluate_script 也纳入此列表：
    # - 终端交互场景下 fill → press_key → evaluate_script 是一个命令的固定三步
    # - 每个命令 3 次工具调用，正常 27 个命令就会触发停滞，远低于合理阈值
    # - evaluate_script 的终端输入操作（sendInput 等）和命令执行（window.__wt.exec/raw）
    #   通过 tool_input 参数在 on_tool_result 中直接判断，参与停滞计数
    _BROWSER_UI_TOOLS = frozenset(
        {
            "click",
            "fill",
            "fill_form",
            "hover",
            "drag",
            "upload_file",
            "take_snapshot",
            "take_screenshot",
            "list_pages",
            "select_page",
            "list_console_messages",
            "get_console_message",
            "list_network_requests",
            "get_network_request",
            "navigate_page",
            "new_page",
            "close_page",
            "resize_page",
            "handle_dialog",
            "wait_for",
            "emulate",
            "wss_connect",
            "press_key",
            "type_text",
            "evaluate_script",
        }
    )

    # evaluate_script 中表示「向终端发送输入」的关键词。
    # 包含这些词的 JS 函数是攻击操作，需要参与重复检测（record_tool_call 阶段）；
    # 不包含则是只读观察（读取 DOM 内容），应跳过。
    _TERMINAL_INPUT_SIGNALS = (
        "sendInput",
        "websocket.send",
        "CLIENT_CMD",
        ".send(",
        "onData",
    )

    def record_tool_call(
        self, tool_name: str, tool_input: Optional[dict] = None
    ) -> None:
        """在 PreToolUse 阶段记录工具调用，用于重复模式检测。

        浏览器 UI 交互/观察工具不记入调用历史（正常导航行为）。
        evaluate_script 例外：包含终端输入操作（sendInput 等）的仍然记入，
        纯读取 DOM 内容的跳过（随 _BROWSER_UI_TOOLS 一起跳过）。
        """
        short_name = (
            tool_name.split("__")[-1] if "__" in tool_name else tool_name
        )
        # evaluate_script 特殊处理（先于 _BROWSER_UI_TOOLS 检查）：
        # 含终端输入信号的是攻击操作，需要参与重复检测
        if short_name == "evaluate_script" and tool_input:
            js_func = tool_input.get("function", "")
            if any(sig in js_func for sig in self._TERMINAL_INPUT_SIGNALS):
                sig = self._make_call_signature(tool_name, tool_input)
                self._call_history.append(sig)
                if len(self._call_history) > self.pattern_window_size * 2:
                    self._call_history = self._call_history[-self.pattern_window_size:]
                return
            # window.__wt.exec / window.__wt.raw 的命令执行也是攻击操作
            if "window.__wt.exec" in js_func or "window.__wt.raw" in js_func:
                sig = self._make_call_signature(tool_name, tool_input)
                self._call_history.append(sig)
                if len(self._call_history) > self.pattern_window_size * 2:
                    self._call_history = self._call_history[-self.pattern_window_size:]
                return
            # 纯读取操作：走 _BROWSER_UI_TOOLS 逻辑跳过
        if short_name in self._BROWSER_UI_TOOLS:
            return
        # wss_exec：提取 command 参数构建签名
        if short_name == "wss_exec" and tool_input:
            cmd = tool_input.get("command", "")
            sig = f"wss_exec:{cmd}"
            self._call_history.append(sig)
            if len(self._call_history) > self.pattern_window_size * 2:
                self._call_history = self._call_history[-self.pattern_window_size:]
            return
        sig = self._make_call_signature(tool_name, tool_input)
        self._call_history.append(sig)
        # 维护窗口大小
        if len(self._call_history) > self.pattern_window_size * 2:
            self._call_history = self._call_history[
                -self.pattern_window_size :
            ]

    def _is_terminal_evaluate_script(
        self, tool_name: str, tool_input: Optional[dict] = None
    ) -> bool:
        """判断 evaluate_script 调用是否为终端命令执行。

        检测 JS 函数中的终端输入信号（sendInput 等）和命令执行
        （window.__wt.exec/raw），这些是真正的攻击操作而非 UI 交互。
        """
        short_name = (
            tool_name.split("__")[-1] if "__" in tool_name else tool_name
        )
        if short_name != "evaluate_script" or not tool_input:
            return False
        js_func = tool_input.get("function", "")
        if any(sig in js_func for sig in self._TERMINAL_INPUT_SIGNALS):
            return True
        if "window.__wt.exec" in js_func or "window.__wt.raw" in js_func:
            return True
        return False

    @staticmethod
    def _parse_field(text: str, field_name: str) -> str:
        """从 record_key_finding 返回文本中解析指定字段值。

        匹配模式: "{field_name}={value}" 其中 value 以 ',' ')' 或空白结束。
        返回小写值字符串，解析失败返回空字符串。
        """
        import re

        pattern = rf"{field_name}=(\S+?)(?:[,)\s]|$)"
        m = re.search(pattern, text)
        return m.group(1).strip().lower() if m else ""

    @staticmethod
    def _compute_mid_value_deduction(status: str, verification: str) -> int:
        """根据 status 和 verification 计算 vulnerability/artifact 的计数器扣减值。

        | status                          | 扣减 |
        |---------------------------------|------|
        | exploited / confirmed           |  -10 |
        | tested                          |   -5 |
        | hypothesis / 其他 + executed    |   -5 |
        | hypothesis / 其他 + observed    |   -3 |
        | hypothesis / 其他 + inferred/其他|  -3 |
        """
        if status in ("exploited", "confirmed"):
            return 10
        if status == "tested":
            return 5
        # hypothesis 或未知状态：仅当 verification=executed 时给 -5，否则 -3
        if verification == "executed":
            return 5
        return 3

    # ── 控制平面方法 ─────────────────────────────────────────────

    @staticmethod
    def _classify_operation(
        tool_name: str, tool_input: Optional[dict]
    ) -> tuple:
        """将工具调用分类为 (operation_class, target_host, surface_key)。

        纯正则，不需要 LLM。分类优先级：
        browser_action → config_read → s3_enum → api_variant → path_scan
        → credential_guess → port_scan → other
        """
        short = tool_name.split("__")[-1] if "__" in tool_name else tool_name
        if short in ReflectionTracker._BROWSER_UI_TOOLS:
            return ("browser_action", "_unknown_", "*")
        if not tool_input:
            return ("other", "_unknown_", "*")

        input_str = json.dumps(tool_input, ensure_ascii=False)

        # 提取 host
        host = "_unknown_"
        host_m = _RE_URL_HOST.search(input_str)
        if host_m:
            host = host_m.group(1).lower()

        def _path_first_seg() -> str:
            pm = _RE_URL_PATH.search(input_str)
            if pm:
                parts = [p for p in pm.group(1).strip("/").split("/") if p]
                if len(parts) >= 2:
                    return f"{parts[0]}/{parts[1]}"
                if parts:
                    return parts[0]
            return "/"

        # config_read（最具体，优先）
        cq = _RE_CONFIG_QUERY.search(input_str)
        if cq:
            return ("config_read", host, cq.group(1).lower())

        # s3_enum
        if _RE_S3_ENUM.search(input_str):
            il = input_str.lower()
            if " ls " in il or "list" in il:
                sf = "ls"
            elif " cp " in il or " mv " in il or "sync" in il:
                sf = "cp"
            elif "presign" in il:
                sf = "presign"
            else:
                sf = "api-query"
            return ("s3_enum", host, sf)

        # api_variant（curl + POST/PUT/PATCH + data）
        if _RE_API_VARIANT.search(input_str):
            method = "POST"
            for m in ("PUT", "PATCH"):
                if m in input_str.upper():
                    method = m
                    break
            return ("api_variant", host, f"{method} /{_path_first_seg()}")

        # 自动化扫描工具归为独立类别，不计入 path_scan
        _il = input_str.lower()
        if any(t in _il for t in ("nuclei ", "nmap ", "ffuf ", "sqlmap ", "nikto ")):
            return ("auto_scan", host, _path_first_seg())

        # path_scan
        if _RE_PATH_SCAN.search(input_str):
            return ("path_scan", host, _path_first_seg())

        # credential_guess
        if _RE_CREDENTIAL_GUESS.search(input_str):
            return ("credential_guess", host, "*")

        # port_scan
        if _RE_PORT_SCAN.search(input_str):
            return ("port_scan", host, "*")

        return ("other", host if host != "_unknown_" else "_unknown_", "*")

    def classify_and_increment(
        self, tool_name: str, tool_input: Optional[dict]
    ) -> None:
        """分类工具调用并递增 bucket streak 计数器。由 PostToolUse 调用。"""
        bucket = self._classify_operation(tool_name, tool_input)
        cls = bucket[0]
        if cls in ("other", "browser_action"):
            return
        self._class_streak[bucket] = self._class_streak.get(bucket, 0) + 1
        self._last_non_other_bucket = bucket

    def check_streak_l2(
        self, tool_name: str, tool_input: Optional[dict]
    ) -> Optional[str]:
        """PreToolUse: 如果即将命中 L2 阈值（5 次），返回 deny reason。

        仅对 path_scan/config_read/s3_enum 起效。
        """
        bucket = self._classify_operation(tool_name, tool_input)
        cls, host, surface = bucket
        if cls not in _L2_ENABLED_CLASSES:
            return None
        count = self._class_streak.get(bucket, 0)
        # PreToolUse 时 count 是已完成的调用数，这将是第 count+1 次
        if count < _L2_THRESHOLD - 1:
            return None
        return (
            f"对 {host} 的 {cls}/{surface} 操作已连续 {count + 1} 次无新 finding，已达预算上限。\n"
            "解除方式（任选其一）：\n"
            "1. record_key_finding（status=tested/confirmed/exploited）记录当前发现\n"
            "2. 切换到不同的 bucket（不同目标或不同操作类型）自然不受影响\n"
            "3. 使用 view_hint 获取方向性线索\n"
            "4. 加载 Skill('stagnation-recovery') 重新规划\n"
            "建议：换一个完全不同的攻击方向，或分析尚未处理的附件/提示。"
        )

    def get_streak_l1_warning(self) -> Optional[str]:
        """PostToolUse: 如果最近一次 classify_and_increment 命中 L1 阈值（3 次），返回警告。"""
        bucket = self._last_non_other_bucket
        if bucket is None:
            return None
        count = self._class_streak.get(bucket, 0)
        if count < _L1_THRESHOLD:
            return None
        # 已提醒过且 count 没到 L2 → 不重复
        if bucket in self._reminded_buckets and count < _L2_THRESHOLD:
            return None
        self._reminded_buckets.add(bucket)
        self._metrics_l1_warn_count += 1
        cls, host, surface = bucket
        surface_display = f"/{surface}" if surface != "*" else ""
        return (
            f"⚠️ 你已经连续 {count} 次对 {host} 执行 {cls}{surface_display} 类操作，"
            "但自上次 finding 以来没有新进展。\n"
            "不要继续同类参数微调。下一步必须先做以下之一："
            "检查遗漏线索（附件、提示、下载链接）、切换到不同 bucket、"
            "使用 view_hint、或加载 Skill('stagnation-recovery')。"
        )

    def _apply_finding_reset(
        self, kind: str, status: str, verification_method: str
    ) -> None:
        """R1-R6 优先级判定：根据 record_key_finding 的三元组重置 bucket streak。

        操作 _last_non_other_bucket 对应的 _class_streak 条目。
        """
        bucket = self._last_non_other_bucket
        if bucket is None or bucket not in self._class_streak:
            return
        c = self._class_streak[bucket]

        # Phase 3 metrics: 如果 bucket 在 L2 阈值以上被 reset，记为 finding_unlock
        was_at_l2 = c >= _L2_THRESHOLD

        # R1-R6 优先级判定
        new_c = c  # 默认不变 (R6)
        if kind == "dead_end":
            new_c = 0  # R1
        elif status in ("confirmed", "exploited") and verification_method == "executed":
            new_c = 0  # R2
        elif status in ("confirmed", "exploited"):
            new_c = max(1, c // 2)  # R3
        elif (
            status == "tested"
            and verification_method == "executed"
            and kind in ("vulnerability", "credential")
        ):
            new_c = max(1, c // 2)  # R4
        elif status == "tested":
            new_c = max(0, c - 1)  # R5
        # R6: hypothesis 或其余 → new_c == c (不变)

        self._class_streak[bucket] = new_c

        # Phase 3: 记录 L2 解锁事件
        if was_at_l2 and new_c < c:
            self._metrics_finding_unlock_after_l2 += 1

    def apply_view_hint_reset(self) -> None:
        """R8: view_hint 调用后，仅衰减 top-2 最热 bucket 的计数。"""
        if not self._class_streak:
            return
        top2 = sorted(self._class_streak.items(), key=lambda x: -x[1])[:2]
        for bucket, count in top2:
            self._class_streak[bucket] = max(0, count // 2)

    def apply_stagnation_recovery_reset(self) -> None:
        """R9: stagnation-recovery Skill 加载后，仅清零被提醒过的 bucket。"""
        for bucket in list(self._reminded_buckets):
            if bucket in self._class_streak:
                self._class_streak[bucket] = 0
        self._reminded_buckets.clear()

    # ── Checkpoint 方法 ──────────────────────────────────────────

    def record_checkpoint_entry(
        self, tool_name: str, tool_input: Optional[dict],
        result_status: str, result_preview: str,
    ) -> None:
        """缓存一条工具调用摘要，供 auto checkpoint 使用。"""
        short = tool_name.split("__")[-1] if "__" in tool_name else tool_name
        input_summary = ""
        if tool_input:
            for key in ("command", "url", "query", "function"):
                if key in tool_input:
                    input_summary = str(tool_input[key])[:80]
                    break
            if not input_summary:
                input_summary = json.dumps(tool_input, ensure_ascii=False)[:60]
        entry = f"- {short}: {input_summary} → {result_status} {result_preview[:100]}"
        self._checkpoint_buffer.append(entry)
        self._calls_since_checkpoint += 1

    def should_write_checkpoint(self) -> bool:
        """每 15 次非 UI 调用返回 True。"""
        return self._calls_since_checkpoint >= _CHECKPOINT_INTERVAL

    def consume_checkpoint_buffer(self) -> tuple:
        """返回 (entries, checkpoint_number) 并重置缓冲区。"""
        self._checkpoint_count += 1
        self._calls_since_checkpoint = 0
        entries = self._checkpoint_buffer[:]
        self._checkpoint_buffer.clear()
        return entries, self._checkpoint_count

    # ── Hint 提醒 ────────────────────────────────────────────────

    def check_hint_reminder(self, is_soft_warn: bool) -> Optional[str]:
        """检查是否应注入 hint 提醒。

        Level 1: SOFT_WARN 触发时 + hint callback 可用 + count < 2
        Level 2: 非 SOFT_WARN + count == 1 + 距首次提醒已过 8 次非 UI 调用
        """
        try:
            from chying_agent.runtime.context import get_hint_callback
            if get_hint_callback() is None:
                return None
        except Exception:
            return None

        # Level 1
        if is_soft_warn and self._hint_remind_count == 0:
            self._hint_remind_count = 1
            self._hint_first_remind_at = self._total_non_ui_calls
            return (
                "💡 当前处于停滞状态。题目提供了 hint（view_hint），"
                "建议使用一个 hint 获取方向性线索。\n"
                "扣分远小于超时未解的损失。"
            )

        # Level 2
        if (
            not is_soft_warn
            and self._hint_remind_count == 1
            and self._hint_first_remind_at > 0
            and self._total_non_ui_calls >= self._hint_first_remind_at + 8
        ):
            self._hint_remind_count = 2
            return (
                "💡 再次提醒：你仍然处于停滞状态，且尚未使用 hint。"
                "view_hint 可以提供方向性线索，扣分远小于超时。"
                "强烈建议现在使用 view_hint。"
            )

        return None

    # ── Phase 2 方法 ─────────────────────────────────────────────

    def get_control_plane_summary(self) -> str:
        """构建控制平面状态摘要，供 guidance query 注入。

        返回空字符串表示没有值得报告的状态。
        """
        lines: list[str] = []
        # bucket streak 警告
        for bucket, count in sorted(
            self._class_streak.items(), key=lambda x: -x[1]
        ):
            if count >= _L1_THRESHOLD:
                cls, host, surface = bucket
                label = (
                    f"({cls}, {host}, {surface})"
                    if surface != "*"
                    else f"({cls}, {host})"
                )
                lines.append(f"- {label}: 连续 {count} 次无新 finding")
        # 全局 finding 缺失
        if self._total_calls_since_finding > 15:
            lines.append(
                f"- 已 {self._total_calls_since_finding} 次操作无 record_key_finding"
            )
        # 停滞警告计数
        if self._reflection_count > 0:
            lines.append(f"- 已触发 {self._reflection_count} 次停滞警告")
        if not lines:
            return ""
        return "## 控制平面状态\n" + "\n".join(lines)

    def get_unconsumed_anomalies(self) -> str:
        """读取 findings.log，提取尚未充分跟进的发现。

        反向扫描 append-only log，按 title 去重取最新状态。
        每个 finding 最多提醒 2 次；status 变更时重置计数。
        """
        try:
            from chying_agent.runtime.context import get_current_work_dir
            work_dir = get_current_work_dir()
            if not work_dir:
                return ""
            findings_file = work_dir / "findings.log"
            if not findings_file.exists():
                return ""
            content = findings_file.read_text(encoding="utf-8")
        except Exception:
            return ""

        # 解析 findings.log：按 ### 分割，提取 kind/title/status
        import re
        entries = re.split(r"(?=^### )", content, flags=re.MULTILINE)
        # 反向去重：保留每个 title 的最新条目
        latest: Dict[str, dict] = {}
        header_re = re.compile(
            r"^### .+? \[(\w+)\] (.+?) \[", re.MULTILINE
        )
        status_re = re.compile(r"^- status:\s*(\S+)", re.MULTILINE)
        evidence_re = re.compile(r"\*\*evidence\*\*:\s*(.+)", re.IGNORECASE)

        for entry in reversed(entries):
            hm = header_re.search(entry)
            if not hm:
                continue
            kind = hm.group(1).lower()
            title = hm.group(2).strip()
            if title in latest:
                continue  # 已有更新的条目
            sm = status_re.search(entry)
            status = sm.group(1).lower() if sm else ""
            em = evidence_re.search(entry)
            evidence = em.group(1).strip()[:120] if em else ""
            latest[title] = {
                "kind": kind, "status": status, "evidence": evidence
            }

        # 筛选：status=tested/confirmed 且不是 dead_end/exploited
        candidates: list[tuple[str, dict]] = []
        for title, info in latest.items():
            if info["kind"] == "dead_end":
                continue
            if info["status"] not in ("tested", "confirmed"):
                continue
            # lifecycle 检查
            old_status = self._anomaly_last_status.get(title)
            remind_count = self._anomaly_remind_count.get(title, 0)
            # status 变更 → 重置计数（agent 确实在跟进）
            if old_status and old_status != info["status"]:
                remind_count = 0
            # 超过 2 次 → 不再提醒
            if remind_count >= 2:
                continue
            candidates.append((title, info))
            # 更新 lifecycle 状态
            self._anomaly_remind_count[title] = remind_count + 1
            self._anomaly_last_status[title] = info["status"]

        if not candidates:
            return ""

        lines = ["## 未充分利用的发现", "以下发现已验证但尚未被充分深挖："]
        for title, info in candidates:
            n = self._anomaly_remind_count[title]
            lines.append(
                f"- {title}: {info['evidence']} "
                f"(status: {info['status']}, 第 {n}/2 次提醒)"
            )
        lines.append("在继续新的枚举之前，优先跟进这些已有线索。")
        return "\n".join(lines)

    def get_last_subagent_stop_reason(self) -> Optional[str]:
        """消费子代理 YAML 中的 stop_reason（一次性读取后清空）。"""
        yaml_data = self._last_subagent_yaml
        if yaml_data is None:
            return None
        self._last_subagent_yaml = None  # 消费后清空
        return yaml_data.get("stop_reason")

    def check_finding_reminder(self) -> Optional[str]:
        """25 次非 UI 调用无 record_key_finding，一次性提醒。"""
        if self._finding_reminder_sent:
            return None
        if self._total_calls_since_finding >= 25 and self._total_non_ui_calls >= 25:
            self._finding_reminder_sent = True
            return (
                f"⚠️ 你已执行 {self._total_non_ui_calls} 次操作但没有 record_key_finding。\n"
                "到目前为止最重要的发现是什么？请用 record_key_finding 记录"
                "（status 为 tested 或 confirmed）。"
            )
        return None

    def get_session_metrics(self) -> Dict[str, Any]:
        """收集会话级控制平面指标，供 session 结束时写入。"""
        streak_values = list(self._class_streak.values())
        stop_reason_dist: Dict[str, int] = {}
        for sr in self._metrics_stop_reasons:
            stop_reason_dist[sr] = stop_reason_dist.get(sr, 0) + 1

        return {
            # 核心指标
            "same_class_streak_max": max(streak_values) if streak_values else 0,
            "auto_checkpoint_count": self._checkpoint_count,
            "hint_remind_count": self._hint_remind_count,
            "hint_used": self._metrics_view_hint_count > 0,
            "finding_count": self._metrics_finding_count,
            # 控制面副作用
            "blocked_by_l2_count": self._metrics_l2_deny_count,
            "finding_unlock_ratio": (
                round(self._metrics_finding_unlock_after_l2 / self._metrics_l2_deny_count, 2)
                if self._metrics_l2_deny_count > 0
                else 0.0
            ),
            # 次要指标
            "time_to_first_finding": self._metrics_first_finding_at,
            "subagent_yaml_parse_ok": self._metrics_yaml_parse_ok,
            "subagent_yaml_parse_fail": self._metrics_yaml_parse_fail,
            "subagent_yaml_parse_rate": (
                round(self._metrics_yaml_parse_ok / (self._metrics_yaml_parse_ok + self._metrics_yaml_parse_fail), 2)
                if (self._metrics_yaml_parse_ok + self._metrics_yaml_parse_fail) > 0
                else None
            ),
            "subagent_stop_reason_distribution": stop_reason_dist,
            # 辅助信息
            "l1_warn_count": self._metrics_l1_warn_count,
            "l2_deny_count": self._metrics_l2_deny_count,
            "soft_warn_count": self._metrics_soft_warn_count,
            "hard_reflect_count": self._reflection_count,
            "abandon_block_count": self._metrics_abandon_block_count,
            "view_hint_count": self._metrics_view_hint_count,
            "total_non_ui_calls": self._total_non_ui_calls,
            "finding_reminder_sent": self._finding_reminder_sent,
            "bucket_streaks": {
                f"{cls},{host},{surface}": count
                for (cls, host, surface), count in self._class_streak.items()
                if count > 0
            },
        }

    def on_tool_result(
        self, tool_name: str, is_error: bool, result_text: str = "",
        tool_input: Optional[dict] = None,
    ) -> ReflectionAction:
        """
        记录工具调用结果，返回应执行的反思动作。

        两阶段机制：
        - 首次触发阈值 → SOFT_WARN（additionalContext 注入，不中断）
        - 软警告后再次触发 → HARD_REFLECT（interrupt + 反思 agent）

        Args:
            tool_name: 工具名称
            is_error: 工具是否返回错误
            result_text: 工具输出文本（用于无效操作检测）
            tool_input: 工具输入参数（用于判断 evaluate_script 是否为终端命令执行）

        Returns:
            ReflectionAction 枚举值
        """
        # record_key_finding：根据发现价值给予不同程度的计数器减免
        if "record_key_finding" in tool_name and not is_error:
            lower_text = result_text.lower()

            # 从返回文本中解析 status 和 verification 字段
            # 格式: "OK: recorded {kind}/{title} (status={status}, verification={verification})"
            parsed_status = self._parse_field(lower_text, "status")
            parsed_verification = self._parse_field(lower_text, "verification")

            # ── 控制平面: 解析 kind 并应用 bucket streak reset（R1-R6）──
            parsed_kind = ""
            for _k in ("dead_end", "flag", "exploit", "credential", "vulnerability",
                       "artifact", "info", "config", "note"):
                if _k in lower_text:
                    parsed_kind = _k
                    break
            self._apply_finding_reset(parsed_kind, parsed_status, parsed_verification)
            # Phase 3: finding 指标
            if parsed_kind not in ("dead_end", ""):
                self._metrics_finding_count += 1
                if self._metrics_first_finding_at is None:
                    self._metrics_first_finding_at = self._total_non_ui_calls
            # ── end control plane ──

            # dead_end 类型：递增 ineffective 计数器（确认失败方向是停滞信号）
            if "dead_end" in lower_text:
                self._ineffective_count += 1
                return ReflectionAction.NONE

            # flag/exploit/credential 是确定性高价值发现：固定扣减 20
            confirmed_signals = frozenset({"flag", "exploit", "credential"})
            if any(k in lower_text for k in confirmed_signals):
                self._consecutive_failures = 0
                self._total_calls_since_finding = max(
                    0, self._total_calls_since_finding - 20
                )
                self._ineffective_count = 0
                self._soft_warning_sent = False
                # 突破性发现：解除 ABANDON 锁定，清空停滞签名，
                # 让 agent 可以自由执行后续验证/提交/保存操作。
                # 如果 agent 再次陷入循环，停滞检测会自然重新介入。
                if self._abandon_active:
                    self._abandon_active = False
                    self._call_history.clear()
                return ReflectionAction.NONE

            # vulnerability/artifact：根据 status+verification 分层扣减
            mid_kind_signals = frozenset({"vulnerability", "artifact"})
            if any(k in lower_text for k in mid_kind_signals):
                deduction = self._compute_mid_value_deduction(
                    parsed_status, parsed_verification
                )
                self._consecutive_failures = 0
                self._total_calls_since_finding = max(
                    0, self._total_calls_since_finding - deduction
                )
                self._ineffective_count = 0
                return ReflectionAction.NONE

            # found/discovered 额外正面信号：固定扣减 5（从 -10 降级）
            if any(k in lower_text for k in self._POSITIVE_EXTRA_SIGNALS):
                self._consecutive_failures = 0
                self._total_calls_since_finding = max(
                    0, self._total_calls_since_finding - 5
                )
                self._ineffective_count = 0
                return ReflectionAction.NONE

            # info/config/note：只重置 ineffective 计数器，
            # 不扣减 no_progress 计数器——防止频繁记录摘要/笔记无限拖延反思
            if any(k in lower_text for k in self._PARTIAL_POSITIVE_KINDS):
                self._ineffective_count = 0
                return ReflectionAction.NONE
            # 负面发现（如 "symlink 不管用"）不重置计数器，但也不算失败
            return ReflectionAction.NONE

        # 浏览器 UI 工具（click/snapshot/fill 等观察/导航操作）：
        # 不参与 no_progress 和 ineffective 计数（与 record_tool_call 保持一致），
        # 但连续错误仍然计数（UI 工具报错说明页面状态有问题）
        #
        # 例外：evaluate_script 中的终端命令执行（window.__wt.exec/raw、sendInput 等）
        # 通过 tool_input 直接判断，这些是真正的攻击操作，必须参与全部停滞计数。
        short_name = (
            tool_name.split("__")[-1] if "__" in tool_name else tool_name
        )
        is_terminal_eval = self._is_terminal_evaluate_script(tool_name, tool_input)
        self._last_result_was_terminal_eval = is_terminal_eval
        if short_name in self._BROWSER_UI_TOOLS and not is_terminal_eval:
            if is_error:
                self._consecutive_failures += 1
            else:
                self._consecutive_failures = 0
            return ReflectionAction.NONE

        self._total_calls_since_finding += 1
        self._total_non_ui_calls += 1

        if is_error:
            self._consecutive_failures += 1
        else:
            self._consecutive_failures = 0
            # 检测「操作成功但实际无效」的信号（case-insensitive）
            if result_text:
                lower_result = result_text.lower()
                if any(
                    sig in lower_result for sig in self._INEFFECTIVE_SIGNALS
                ):
                    self._ineffective_count += 1

        # 已达反思上限，不再触发
        if self._reflection_count >= self.max_reflections:
            return ReflectionAction.NONE

        # 早期豁免：前 N 次非 UI 工具调用内不触发反思，让 agent 有充足的探索空间。
        # 计数器正常累积，只是不做触发判断。累积计数不会被反思重置（过了早期就是过了）。
        if self._total_non_ui_calls < self.early_phase_immunity:
            return ReflectionAction.NONE

        # 四层检测
        triggered = (
            # 层 1：连续错误
            self._consecutive_failures >= self.consecutive_failure_threshold
            # 层 2：长期无进展
            or self._total_calls_since_finding >= self.no_progress_threshold
            # 层 3：重复模式（换汤不换药）
            or self._check_repetition()
            # 层 4：大量无效操作（成功但实际不起作用）
            or self._ineffective_count >= self.ineffective_threshold
        )

        if not triggered:
            return ReflectionAction.NONE

        # 记录触发原因（在计数器重置前，供 build_soft_warning_text 使用）
        reasons: list[str] = []
        if self._consecutive_failures >= self.consecutive_failure_threshold:
            reasons.append(f"连续工具错误: {self._consecutive_failures} 次 (阈值 {self.consecutive_failure_threshold})")
        if self._total_calls_since_finding >= self.no_progress_threshold:
            reasons.append(f"无正面发现的工具调用: {self._total_calls_since_finding} 次 (阈值 {self.no_progress_threshold})")
        if self._check_repetition():
            reasons.append("检测到重复操作模式")
        if self._ineffective_count >= self.ineffective_threshold:
            reasons.append(f"无效操作（Permission denied 等）: {self._ineffective_count} 次 (阈值 {self.ineffective_threshold})")
        self._last_trigger_reasons = reasons

        # --- 两阶段分支 ---
        if not self._soft_warning_sent:
            # 第一阶段：软警告，不中断
            self._soft_warning_sent = True
            self._metrics_soft_warn_count += 1
            # 1/2 阈值重置：给 agent 充足的缓冲窗口消化软警告并调整策略
            # 比如 no_progress_threshold=50 时，重置为 25，软警告后还有 25 次调用窗口
            self._consecutive_failures = self.consecutive_failure_threshold // 2
            self._total_calls_since_finding = self.no_progress_threshold // 2
            self._ineffective_count = self.ineffective_threshold // 2
            self._call_history = self._call_history[-(self.pattern_window_size // 2):]
            return ReflectionAction.SOFT_WARN
        else:
            # 第二阶段：硬反思，中断 + 反思 agent
            self._reflection_count += 1
            self._soft_warning_sent = False
            self._consecutive_failures = 0
            self._total_calls_since_finding = 0
            self._ineffective_count = 0
            self._call_history.clear()
            # 反思后启动 todo 执行提醒窗口（前 5 次非 UI 工具调用持续提醒）
            self._post_reflection_reminder_countdown = 5
            return ReflectionAction.HARD_REFLECT

    @property
    def reflection_count(self) -> int:
        return self._reflection_count

    def check_synthesis_reminder(self) -> Optional[str]:
        """每隔 _synthesis_interval 次非 UI 工具调用，返回攻击链综合提醒。

        由 PostToolUse hook 在 on_tool_result 返回 NONE 且无 post-reflection 提醒时调用。
        调用方负责过滤浏览器 UI 工具（与 consume_post_reflection_reminder 一致）。
        """
        self._calls_since_last_synthesis += 1
        if self._calls_since_last_synthesis < self._synthesis_interval:
            return None
        self._calls_since_last_synthesis = 0
        return (
            "ATTACK CHAIN SYNTHESIS CHECKPOINT: "
            "Pause and combine ALL discoveries so far into potential attack chains. "
            "For each chain, identify: (1) what you have, (2) what is missing, (3) how to get it. "
            "If you identified specific technologies/products but lack exploitation knowledge, "
            "call kb_search with precise keywords (product name, vulnerability type, CVE). "
            "If you have 3+ key findings that have not been connected, "
            "call record_key_finding(kind='vulnerability', title='Attack Chain Hypothesis: ...', "
            "evidence='<key data points that form the chain>') "
            "to document your synthesis before continuing."
        )

    def check_progress_reminder(self) -> Optional[str]:
        """每隔 _progress_interval 次非 UI 工具调用，提醒 agent 更新 progress.md。

        由 PostToolUse hook 在 on_tool_result 返回 NONE 且无其他提醒时调用。
        调用方负责过滤浏览器 UI 工具（与 check_synthesis_reminder 一致）。
        """
        self._calls_since_last_progress_reminder += 1
        if self._calls_since_last_progress_reminder < self._progress_interval:
            return None
        self._calls_since_last_progress_reminder = 0
        return (
            "PROGRESS UPDATE CHECKPOINT: "
            "Read progress.md in the current work directory. "
            "Attack Tree and Dead Ends are auto-synced from record_key_finding, DO NOT manually Edit them. "
            "Use record_key_finding(kind='dead_end', ...) to add failed approaches. "
            "You may update 'Current Phase' section with your current status. "
            "This file is your recovery anchor after context compaction."
        )

    def check_skill_hint_reminder(self) -> bool:
        """每隔 _skill_hint_interval 次工具调用（含 UI 工具），返回 True 表示应注入 skill hints。

        与 check_synthesis_reminder 不同，此方法统计所有工具调用（包括浏览器 UI 工具），
        确保 agent 在长时间 chrome-devtools 操作期间仍能收到 skill 描述提醒。
        """
        self._calls_since_last_skill_hint += 1
        if self._calls_since_last_skill_hint < self._skill_hint_interval:
            return False
        self._calls_since_last_skill_hint = 0
        return True

    def consume_post_reflection_reminder(self) -> Optional[str]:
        """如果在 post-reflection 提醒窗口内，返回提醒文本并递减计数器。

        由 PostToolUse hook 在 on_tool_result 返回 NONE 后调用。
        调用方负责过滤浏览器 UI 工具（不应消耗倒计数）。
        """
        if self._post_reflection_reminder_countdown <= 0:
            return None
        self._post_reflection_reminder_countdown -= 1
        remaining = self._post_reflection_reminder_countdown
        if remaining == 0:
            label = "final checkpoint"
        else:
            label = f"{remaining} remaining"
        return (
            f"[POST-REFLECTION CHECKPOINT] ({label}): "
            "You MUST be executing the first in_progress task from your TodoWrite plan. "
            "If your current action does not align with that task, STOP and re-read your todo list."
        )

    def get_stagnation_signatures(self, n: int = 8) -> list[str]:
        """返回 ABANDON 激活前的最后 N 次调用签名，用于 PreToolUse 匹配。

        当 _abandon_active 时，从 _call_history 中提取最后 N 条唯一签名。
        这些签名代表导致停滞的调用模式，PreToolUse 可用来拦截同模式的新调用。

        Args:
            n: 返回的最大签名数量

        Returns:
            签名列表（去重，保持时序）
        """
        if not self._call_history:
            return []
        # 去重但保持顺序（后出现的优先）
        seen: set[str] = set()
        unique: list[str] = []
        for sig in reversed(self._call_history):
            if sig not in seen:
                seen.add(sig)
                unique.append(sig)
            if len(unique) >= n:
                break
        unique.reverse()
        return unique

    # ---- 反思报告管理 ----

    def set_last_reflection_report(self, report: str) -> None:
        """存储最近一次反思报告"""
        self._last_reflection_report = report

    @property
    def last_reflection_report(self) -> Optional[str]:
        """最近一次反思报告"""
        return self._last_reflection_report



def build_soft_warning_text(tracker: ReflectionTracker) -> tuple[str, str]:
    """构建软警告文本，拆分为 reason（强提示）和 context（详细清单）。

    返回 (reason_text, context_text)：
    - reason_text: 简短直接的警告，通过 PostToolUse decision:"block" 的 reason 字段
      主动推送给 Claude（"prompts Claude with the reason"），不可忽略。
    - context_text: 详细的自查清单，通过 additionalContext 注入作为补充上下文。

    Args:
        tracker: ReflectionTracker 实例

    Returns:
        (reason_text, context_text) 元组
    """
    if tracker._last_trigger_reasons:
        diag_text = "\n".join(f"- {r}" for r in tracker._last_trigger_reasons)
    else:
        diag_text = "- Multiple stagnation indicators near threshold"

    # reason: 简短、直接、不可忽略的强提示
    reason_text = (
        "STAGNATION DETECTED — Action required before continuing.\n"
        f"Triggers:\n{diag_text}\n\n"
        "MANDATORY: Before your next tool call, you MUST do ALL of the following:\n"
        "1. Call record_key_finding to persist your current discoveries\n"
        "2. Update progress.md with current phase and findings\n"
        "3. Evaluate whether your current approach is working — if not, pivot NOW\n"
        "4. Perform a Hypothesis Audit: list your top 3 assumptions about the target.\n"
        "   For each: \"What evidence supports this? What would DISPROVE it?\"\n"
        "   If any assumption lacks evidence, that is likely where your model is wrong.\n\n"
        "If stagnation continues, the system will force a full reflection interruption."
    )

    # context: 领域专用的停滞诊断和恢复指令
    context_text = (
        "**DIAGNOSE your stagnation mode FIRST:**\n"
        "- **Mode A (Looping)**: Retrying same tool with different params? "
        "STOP. Pick a fundamentally different attack vector from the attack tree.\n"
        "- **Mode B (Hard constraint)**: Permission denied / tool missing / network blocked? "
        "First distinguish: is this blocking the METHOD or the DIRECTION? "
        "List 3+ alternative methods before declaring a direction dead. "
        "Example: 'CA blocks ROPC' blocks only ROPC — interactive login, device code, admin consent "
        "are separate methods with independent CA evaluation. "
        "Workarounds: no compiler -> transfer binary; no outbound -> use existing channel; "
        "read-only FS -> /tmp or /dev/shm; needs MFA -> device_code flow.\n"
        "- **Mode C (Blind attacking)**: Guessing endpoints/params without recon? "
        "STOP attacking. Go back to recon: enumerate, read docs, scan ports, find source.\n"
        "- **Mode D (Disconnected findings)**: Multiple discoveries but no attack chain? "
        "List ALL key findings, try combining every pair: cred+service, vuln+endpoint, leak+privilege.\n"
        "- **Mode E (Tool misuse)**: curl/shell commands keep failing on encoding/escaping? "
        "Switch to Python script immediately (requests lib). No more manual curl.\n"
        "- **Mode F (Knowledge gap)**: You know what technology/product is involved but don't know "
        "how to exploit it? Call mcp__chying__kb_search with specific technical keywords "
        "(e.g., 'terraform state poisoning', 'kubernetes RBAC abuse', product name + CVE). "
        "The knowledge base has 2800+ attack technique documents. "
        "Search triggers: software version number found in recon → search 'ProductName version exploit'; "
        "error message with product name → search exact error string; "
        "3 standard web vectors (sqli/xss/ssrf) all failed → search 'ProductName attack techniques'.\n"
        "- **Mode G (Untracked clues)**: Found URLs, error codes, or references you haven't followed up on? "
        "Check findings.log for all next_action and paths_not_tried entries. "
        "WebFetch any discovered URLs (especially redirect URIs, error doc links). "
        "Also: call kb_search with the software name or error message you observed — "
        "untracked clues AND unqueried knowledge are the #1 source of missed solutions.\n\n"
        "**Recovery rules:**\n"
        "- Deepen directions with PARTIAL progress before trying new ones\n"
        "- Each new direction must be fundamentally different (not a param tweak)\n"
        "- After 3 failures on a direction, abandon it and pick the next one\n"
        "- Call Skill(\"stagnation-recovery\") for the full attack tree and methodology"
    )

    return reason_text, context_text


__all__ = [
    "ReflectionAction",
    "ReflectionTracker",
    "build_soft_warning_text",
    "get_current_log_file_path",
    "get_current_memory_path",
    "get_current_work_dir_str",
    "persist_session_summary",
    "read_reflection_history",
    "extract_dead_ends",
    "extract_prior_findings",
]

