"""
Session JSONL 解析器

解析 Claude Agent SDK 生成的 session jsonl 文件，
提取 Agent 分析流程用于前端可视化展示。

Claude SDK JSONL 格式说明：
- type: "user" - 用户消息，message.content 为字符串或包含 tool_result 的数组
- type: "assistant" - 助手消息，message.content 为数组，包含 text 或 tool_use
- type: "summary" - 会话摘要
- type: "queue-operation" - 队列操作（忽略）

适配自 GangTrace 项目，用于 CHYing-agent CTF 渗透测试场景。
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from .session_utils import find_subagent_files

# 模块级 logger
logger = logging.getLogger(__name__)


class SessionParser:
    """Session JSONL 解析器 - 适配 Claude SDK 格式"""

    def __init__(self, jsonl_path: str, include_subagents: bool = True):
        """
        初始化解析器

        Args:
            jsonl_path: session jsonl 文件路径
            include_subagents: 是否包含子代理的执行过程
        """
        self.jsonl_path = Path(jsonl_path)
        self.include_subagents = include_subagents

    def parse(self) -> Dict[str, Any]:
        """
        解析 session jsonl 文件

        Returns:
            解析后的结构化数据，包含：
            - steps: 分析步骤列表
            - summary: 统计摘要
            - metadata: 元数据
            - subagents: 子代理列表（如果 include_subagents=True）
        """
        if not self.jsonl_path.exists():
            logger.warning(f"Session 文件不存在: {self.jsonl_path}")
            return {
                "success": False,
                "error": f"文件不存在: {self.jsonl_path}",
                "steps": [],
                "summary": {},
                "metadata": {},
                "subagents": [],
            }

        # 解析主会话
        result = self._parse_single_file(self.jsonl_path)

        # 解析子代理
        if self.include_subagents and result.get("success"):
            session_id = result.get("metadata", {}).get("session_id")
            if session_id:
                subagent_files = find_subagent_files(
                    session_id, self.jsonl_path.parent
                )
                subagents = []
                for subagent_file in subagent_files:
                    subagent_result = self._parse_single_file(
                        subagent_file, is_subagent=True
                    )
                    if subagent_result.get("success"):
                        # 提取 agentId
                        agent_id = subagent_file.stem.replace("agent-", "")
                        subagent_result["agent_id"] = agent_id
                        subagents.append(subagent_result)

                result["subagents"] = subagents
            else:
                result["subagents"] = []
        else:
            result["subagents"] = []

        return result

    def _parse_single_file(
        self, file_path: Path, is_subagent: bool = False
    ) -> Dict[str, Any]:
        """
        解析单个 JSONL 文件

        Args:
            file_path: JSONL 文件路径
            is_subagent: 是否是子代理文件

        Returns:
            解析后的结构化数据
        """

        steps = []
        tool_calls = 0
        tool_results = 0
        thinking_count = 0
        user_messages = 0
        tool_breakdown: dict[str, int] = {}
        start_time = None
        end_time = None
        session_id = None
        agent_id = None
        model = None

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        event = json.loads(line)
                        parsed_steps = self._parse_event(event, is_subagent)

                        for step in parsed_steps:
                            steps.append(step)

                            # 统计
                            if step["type"] == "tool_call":
                                tool_calls += 1
                                tool_name = step.get("tool", "unknown")
                                tool_breakdown[tool_name] = tool_breakdown.get(tool_name, 0) + 1
                            elif step["type"] == "tool_result":
                                tool_results += 1
                            elif step["type"] == "thinking":
                                thinking_count += 1
                            elif step["type"] == "user_message":
                                user_messages += 1

                            # 时间范围
                            if step.get("timestamp"):
                                ts = step["timestamp"]
                                if start_time is None or ts < start_time:
                                    start_time = ts
                                if end_time is None or ts > end_time:
                                    end_time = ts

                        # 提取元数据
                        if not session_id and event.get("sessionId"):
                            session_id = event.get("sessionId")
                        if not agent_id and event.get("agentId"):
                            agent_id = event.get("agentId")
                        if not model and event.get("message", {}).get("model"):
                            model = event.get("message", {}).get("model")

                    except json.JSONDecodeError as e:
                        logger.warning(f"JSON 解析错误 (行 {line_num}): {e}")
                        continue

        except Exception as e:
            logger.error(f"读取 session 文件失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "steps": [],
                "summary": {},
                "metadata": {},
            }

        # 计算持续时间
        duration_seconds = None
        if start_time and end_time:
            try:
                start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
                duration_seconds = (end_dt - start_dt).total_seconds()
            except Exception:
                pass

        return {
            "success": True,
            "steps": steps,
            "summary": {
                "total_steps": len(steps),
                "user_messages": user_messages,
                "thinking_count": thinking_count,
                "tool_calls": tool_calls,
                "tool_results": tool_results,
                "duration_seconds": duration_seconds,
                "tool_breakdown": tool_breakdown,
            },
            "metadata": {
                "file_path": str(file_path),
                "session_id": session_id,
                "agent_id": agent_id,
                "model": model,
                "start_time": start_time,
                "end_time": end_time,
                "is_subagent": is_subagent,
            },
        }

    def _parse_event(
        self, event: Dict[str, Any], is_subagent: bool = False
    ) -> List[Dict[str, Any]]:
        """
        解析单个事件，可能返回多个步骤

        Claude SDK 的一个事件可能包含多个内容块（如多个 tool_use）

        Args:
            event: 原始事件数据
            is_subagent: 是否是子代理

        Returns:
            解析后的步骤列表
        """
        event_type = event.get("type", "")
        timestamp = event.get("timestamp", "")
        message = event.get("message", {})

        steps = []

        # 用户消息
        if event_type == "user":
            content = message.get("content", "")

            # content 可能是字符串或数组
            if isinstance(content, str):
                # 普通用户消息
                if content.strip():
                    steps.append(
                        {
                            "type": "user_message",
                            "content": content,
                            "timestamp": timestamp,
                        }
                    )
            elif isinstance(content, list):
                # 包含 tool_result 的消息
                for item in content:
                    if isinstance(item, dict):
                        item_type = item.get("type", "")
                        if item_type == "tool_result":
                            # 工具结果
                            tool_content = item.get("content", [])
                            result_text = self._extract_tool_result_text(tool_content)
                            steps.append(
                                {
                                    "type": "tool_result",
                                    "tool_use_id": item.get("tool_use_id", ""),
                                    "output": self._simplify_output(result_text),
                                    "success": not item.get("is_error", False),
                                    "timestamp": timestamp,
                                }
                            )

        # 助手消息
        elif event_type == "assistant":
            content = message.get("content", [])

            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        item_type = item.get("type", "")

                        if item_type == "text":
                            # 思考/回复文本
                            text = item.get("text", "")
                            if text.strip():
                                steps.append(
                                    {
                                        "type": "thinking",
                                        "content": text,
                                        "timestamp": timestamp,
                                    }
                                )

                        elif item_type == "tool_use":
                            # 工具调用
                            steps.append(
                                {
                                    "type": "tool_call",
                                    "tool": item.get("name", ""),
                                    "tool_use_id": item.get("id", ""),
                                    "input": self._simplify_input(
                                        item.get("input", {})
                                    ),
                                    "timestamp": timestamp,
                                }
                            )

        # 会话摘要（可选展示）
        elif event_type == "summary":
            summary_text = event.get("summary", "")
            if summary_text:
                steps.append(
                    {"type": "summary", "content": summary_text, "timestamp": timestamp}
                )

        # 忽略的事件类型：queue-operation, file-history-snapshot 等

        return steps

    def _extract_tool_result_text(self, content: Any) -> str:
        """
        从 tool_result 的 content 中提取文本

        Args:
            content: tool_result 的 content 字段

        Returns:
            提取的文本内容
        """
        if isinstance(content, str):
            return content
        elif isinstance(content, list):
            texts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    texts.append(item.get("text", ""))
                elif isinstance(item, str):
                    texts.append(item)
            return "\n".join(texts)
        return str(content)

    def _simplify_input(self, input_data: Any, max_str_len: int = 500) -> Any:
        """
        简化工具输入（避免数据过大）

        Args:
            input_data: 原始输入
            max_str_len: 字符串最大长度

        Returns:
            简化后的输入
        """
        if isinstance(input_data, dict):
            simplified = {}
            for key, value in input_data.items():
                simplified[key] = self._simplify_input(value, max_str_len)
            return simplified
        elif isinstance(input_data, list):
            if len(input_data) > 10:
                return input_data[:10] + [f"... 共 {len(input_data)} 项"]
            return [self._simplify_input(item, max_str_len) for item in input_data]
        elif isinstance(input_data, str) and len(input_data) > max_str_len:
            return input_data[:max_str_len] + f"... (共 {len(input_data)} 字符)"
        return input_data

    def _simplify_output(self, output: Any, max_str_len: int = 2000) -> Any:
        """
        简化工具输出（避免数据过大）

        Args:
            output: 原始输出
            max_str_len: 字符串最大长度

        Returns:
            简化后的输出
        """
        if isinstance(output, str):
            # 尝试解析 JSON
            try:
                parsed = json.loads(output)
                return self._simplify_output(parsed, max_str_len)
            except json.JSONDecodeError:
                pass

            # 截断长字符串
            if len(output) > max_str_len:
                return output[:max_str_len] + f"\n... (共 {len(output)} 字符)"
            return output

        elif isinstance(output, dict):
            simplified = {}
            for key, value in output.items():
                simplified[key] = self._simplify_output(value, max_str_len)
            return simplified

        elif isinstance(output, list):
            if len(output) > 10:
                simplified = [
                    self._simplify_output(item, max_str_len) for item in output[:10]
                ]
                simplified.append({"_truncated": True, "_total": len(output)})
                return simplified
            return [self._simplify_output(item, max_str_len) for item in output]

        return output


# ============== 便捷函数 ==============


def parse_session_file(jsonl_path: str) -> Dict[str, Any]:
    """
    解析 session jsonl 文件的便捷函数

    Args:
        jsonl_path: session jsonl 文件路径

    Returns:
        解析后的结构化数据
    """
    parser = SessionParser(jsonl_path)
    return parser.parse()


def get_session_steps(jsonl_path: str) -> List[Dict[str, Any]]:
    """
    获取 session 的步骤列表

    Args:
        jsonl_path: session jsonl 文件路径

    Returns:
        步骤列表
    """
    result = parse_session_file(jsonl_path)
    return result.get("steps", [])


__all__ = [
    # 解析器
    "SessionParser",
    "parse_session_file",
    "get_session_steps",
]
