"""
结构化输出 Schema 定义
========================

提供 Orchestrator 输出 Schema，用于 ClaudeOrchestrator 的最终结构化输出。
"""

from typing import Any, Dict


# ============== Orchestrator 输出 Schema ==============
#
# 用于 `ClaudeOrchestrator` 的最终输出，供上层稳定解析。
#
ORCHESTRATOR_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "description": "CHYing Orchestrator 最终输出结构",
    "properties": {
        "solved": {
            "type": "boolean",
            "description": "是否成功拿到可提交的 flag",
        },
        "flag": {
            "anyOf": [{"type": "string"}, {"type": "null"}],
            "description": "FLAG 值（如 solved=true）",
        },
        "summary": {
            "type": "string",
            "description": "简要总结（不要包含长输出）",
        },
        "evidence": {
            "type": "array",
            "items": {"type": "string"},
            "description": "关键证据要点（命令/文件路径/响应特征等），每条尽量短",
        },
        "artifacts": {
            "type": "array",
            "description": "产物/落盘文件指针（如长输出文件、PoC 文件等）",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "description": {"type": "string"},
                },
                "required": ["path"],
            },
        },
        "next_steps": {
            "type": "array",
            "items": {"type": "string"},
            "description": "如果未 solved，给出下一步建议（最多 5 条）",
        },
        "blocked_reason": {
            "anyOf": [{"type": "string"}, {"type": "null"}],
            "description": "失败阻塞点（如环境限制/缺少凭据/目标不可达等）",
        },
        "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1,
            "description": "对结论的置信度（0-1）",
        },
        "recon_complete": {
            "type": "boolean",
            "description": (
                "侦察阶段是否完成。当你已充分枚举目标攻击面、"
                "识别了多个可能的攻击向量后，设为 true 并填写 attack_vectors。"
                "系统将根据攻击面数量决定是否启动分支探索。"
                "仅在发现 2+ 个不同攻击向量时使用。"
            ),
        },
        "attack_vectors": {
            "type": "array",
            "description": "发现的攻击向量列表（仅 recon_complete=true 时填写）",
            "items": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "攻击向量名称（如 'Grafana SSRF via Infinity plugin'）",
                    },
                    "description": {
                        "type": "string",
                        "description": "具体描述和已有证据",
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                        "description": "优先级",
                    },
                },
                "required": ["name", "description", "priority"],
            },
        },
    },
    "required": ["solved", "flag", "summary", "evidence", "next_steps"],
}


__all__ = [
    "ORCHESTRATOR_OUTPUT_SCHEMA",
]
