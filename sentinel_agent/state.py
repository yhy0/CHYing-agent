"""
状态定义模块
============

定义 Sentinel Agent 的状态结构和 reduce 函数。

设计理念：
- 使用 TypedDict 提供类型安全
- 定义 reduce 函数统一处理列表字段的合并逻辑
- 支持 LangGraph ToolNode 架构（messages 字段）
- 清晰的状态字段分类
"""
from typing import List, Dict, Optional, TypedDict, Annotated, Sequence, Callable
from operator import add
from langchain_core.messages import BaseMessage, ToolMessage, HumanMessage


def merge_by_unique_key(key: str) -> Callable[[List[Dict], List[Dict]], List[Dict]]:
    """
    创建一个基于唯一键的列表合并函数（高阶函数）
    
    这是一个工厂函数，返回一个去重合并函数。
    避免重复添加同一条记录（基于指定的唯一键）。
    
    Args:
        key: 用于去重的键名（如 "vuln_id"）
        
    Returns:
        一个合并函数，接受两个列表并返回合并后的列表
        
    Example:
        >>> merge_vulns = merge_by_unique_key("vuln_id")
        >>> left = [{"vuln_id": "v1", "name": "XSS"}]
        >>> right = [{"vuln_id": "v1", "name": "XSS"}, {"vuln_id": "v2", "name": "SQLi"}]
        >>> merge_vulns(left, right)
        [{"vuln_id": "v1", "name": "XSS"}, {"vuln_id": "v2", "name": "SQLi"}]
    """
    def merge_func(left: List[Dict], right: List[Dict]) -> List[Dict]:
        merged = left.copy()
        for item in right:
            # 仅在键存在且值不重复时添加
            if key in item and not any(
                existing.get(key) == item[key] for existing in merged
            ):
                merged.append(item)
        return merged
    return merge_func


# 创建具体的合并函数实例
merge_tried_exploits = merge_by_unique_key("vuln_id")
merge_vulnerabilities = merge_by_unique_key("vuln_id")


def compress_messages(left: Sequence[BaseMessage], right: Sequence[BaseMessage]) -> Sequence[BaseMessage]:
    """
    消息压缩合并函数 - 只保留最近的工具消息，旧消息合并为摘要

    策略：
    1. 保留所有非工具消息（AI、Human、System）
    2. 只保留最近 5 条工具消息
    3. 将旧的工具消息合并为一条摘要

    ⚠️ 设计说明：
    - 不需要保留"关键消息"，因为 FLAG 提交成功后 Agent 会立即退出
    - 每个题目使用独立的 state，不会跨题目共享消息
    - 保持消息的时间顺序（AI 消息和对应的工具结果不分离）
    - 去重旧的摘要消息（避免摘要累积）

    Args:
        left: 现有消息列表
        right: 新增消息列表

    Returns:
        压缩后的消息列表
    """
    MAX_RECENT_TOOL_MESSAGES = 10  # 只保留最近 10 条工具消息

    # 合并所有消息
    all_messages = list(left) + list(right)

    # ⭐ 改进 1: 先移除旧的摘要消息（避免摘要累积）
    filtered_messages = []
    for msg in all_messages:
        # 跳过旧的摘要消息
        if isinstance(msg, HumanMessage) and msg.content.startswith("📦 **历史工具调用摘要**"):
            continue
        filtered_messages.append(msg)

    # ⭐ 改进 2: 标记工具消息的索引（保持顺序）
    tool_message_indices = []

    for idx, msg in enumerate(filtered_messages):
        if isinstance(msg, ToolMessage):
            tool_message_indices.append(idx)

    # 如果工具消息超过限制，进行压缩
    tool_count = len(tool_message_indices)
    if tool_count > MAX_RECENT_TOOL_MESSAGES:
        # 保留最近的 N 条工具消息的索引
        recent_tool_indices = set(tool_message_indices[-MAX_RECENT_TOOL_MESSAGES:])
        old_tool_indices = set(tool_message_indices[:-MAX_RECENT_TOOL_MESSAGES])

        # 收集需要压缩的旧工具消息
        old_tool_messages = []
        for idx in old_tool_indices:
            old_tool_messages.append(filtered_messages[idx])

        # 创建摘要
        summary_parts = []
        for msg in old_tool_messages:
            tool_name = getattr(msg, 'name', 'unknown')
            content_preview = msg.content[:200] if msg.content else ""
            summary_parts.append(f"- [{tool_name}]: {content_preview}...")

        summary_content = (
            f"📦 **历史工具调用摘要**（已压缩 {len(old_tool_messages)} 条消息）\n\n"
            + "\n".join(summary_parts)
        )
        summary_message = HumanMessage(content=summary_content)

        # ⭐ 改进 3: 保持消息顺序，只替换旧的工具消息
        result = []
        summary_inserted = False

        for idx, msg in enumerate(filtered_messages):
            # 跳过旧的工具消息
            if idx in old_tool_indices:
                # 在第一个被跳过的位置插入摘要
                if not summary_inserted:
                    result.append(summary_message)
                    summary_inserted = True
                continue

            # 保留其他所有消息（最近的工具消息、AI/Human/System 消息）
            result.append(msg)

        # 日志输出
        import logging
        from sentinel_agent.common import log_system_event
        log_system_event(
            f"[消息压缩] 压缩旧工具消息",
            {
                "total_tool_messages": tool_count,
                "compressed": len(old_tool_messages),
                "kept_recent": len(recent_tool_indices)
            }
        )

        return result
    else:
        # 不需要压缩，返回过滤后的消息（已移除旧摘要）
        return filtered_messages


class PenetrationTesterState(TypedDict):
    """
    渗透测试 Agent 的状态
    
    字段说明：
    - messages: LangGraph 消息序列（用于 ToolNode 架构）
    - open_ports: 开放的端口列表
    - service_info: 服务信息字典 {port: "service_name_version"}
    - potential_vulnerabilities: 潜在漏洞列表（使用 merge_vulnerabilities 合并）
    - tried_exploits: 已尝试的漏洞列表（使用 merge_tried_exploits 合并）
    - last_exploit_status: 最后一次利用状态（用于路由决策）
    - last_action_output: 最后一次操作的输出
    - flag: 找到的 FLAG
    - is_finished: 是否完成任务
    - action_history: 操作历史（使用 add 合并）
    - evidence_chain_ids: 证据链 ID 列表（使用 add 合并）
    - current_snapshot_id: 当前快照 ID
    - last_node: 最后一个执行的业务节点名称（用于 ToolNode 路由）
    """
    # --- LangGraph 消息流（ToolNode 架构核心）---
    messages: Annotated[Sequence[BaseMessage], compress_messages]
    
    # --- CTF 比赛相关 ---
    challenges: Optional[List[Dict]]  # 赛题列表（从 API 获取）
    current_challenge: Optional[Dict]  # 当前赛题（包含目标 URL）
    completed_challenges: Annotated[List[str], add]  # 已完成的赛题代码列表
    
    # --- 题目统计 ---
    total_challenges: int  # 总题数
    solved_count: int  # 已解答题数
    unsolved_count: int  # 未解答题数
    hint_used_count: int  # 已使用提示次数
    attempts_count: int  # 当前题目尝试次数
    
    # --- 比赛状态（新增）---
    current_score: int  # 当前总积分
    start_time: Optional[float]  # 比赛开始时间（时间戳）
    current_phase: Optional[str]  # 当前阶段（debug/competition）
    
    # --- 传统渗透测试信息 ---
    open_ports: List[int]
    service_info: Dict[int, str]

    # --- 分析与决策 ---
    potential_vulnerabilities: Annotated[List[Dict], merge_vulnerabilities]
    tried_exploits: Annotated[List[Dict], merge_tried_exploits]
    last_exploit_status: Optional[str]  # "success", "failed", "none"
    last_attempt_result: Optional[str]  # 最后一次尝试的结果
    last_fail_reason: Optional[str]  # 最后一次失败原因
    last_reflection: Optional[str]  # 最后一次反思
    
    # --- 执行与结果 ---
    last_action_output: str  # 好像是废弃的
    flag: Optional[str]
    is_finished: bool

    # --- 审计与元数据 ---
    action_history: Annotated[List[str], add]
    evidence_chain_ids: Annotated[List[str], add]
    current_snapshot_id: str  # = "initial_snapshot"
    last_node: str  # 最后一个业务节点名称（用于 ToolNode 返回路由）

    # --- 多 Agent 协作 ---
    advisor_suggestion: Optional[str]  # 顾问 Agent 的建议（多 Agent 模式）

    # --- 智能路由控制（优化：减少不必要的 Advisor 调用）---
    consecutive_failures: int  # 连续失败次数（用于判断是否需要 Advisor 介入）
    last_action_type: Optional[str]  # 上次执行的操作类型（用于检测重复尝试）
    request_advisor_help: bool  # Main Agent 主动请求 Advisor 帮助的标记
    last_advisor_at_failures: int  # ⭐ 新增：上次咨询 Advisor 时的失败次数（避免重复触发）

