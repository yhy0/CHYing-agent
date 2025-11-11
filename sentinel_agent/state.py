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
from langchain_core.messages import BaseMessage


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
    messages: Annotated[Sequence[BaseMessage], add]
    
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
    last_action_output: str
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

