"""\
Prompt Compiler
===============

Prompt 编译器：接收结构化的题目数据，利用 prompt engineering 最佳实践，
输出一段 XML 结构化的动态片段。最终 metadata 由代码注入给 Orchestrator。

内部集成 RAG 查询：编译前自动检索知识库，将相关文档注入 LLM 编译输入。
单轮推理，无工具，输出纯文本。
"""

import logging
import os
from typing import Optional, Any, Dict, List

from ..claude_sdk import BaseClaudeAgent
from ..common import log_system_event
from ..utils.path_utils import get_host_agent_work_dir
from .prompt_compiler_meta import COMPILER_SYSTEM_PROMPT


class PromptCompiler(BaseClaudeAgent):
    """Prompt 编译器：将原始题目数据优化为 XML 动态段落片段。"""

    def __init__(
        self,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        _model = model or os.getenv("LLM_MODEL") or None
        _api_key = api_key or os.getenv("LLM_API_KEY") or None
        _base_url = base_url or os.getenv("LLM_BASE_URL") or None
        _cwd = str(get_host_agent_work_dir())

        super().__init__(
            model=_model,
            system_prompt=COMPILER_SYSTEM_PROMPT,
            max_turns=1,
            enable_hooks=False,
            cwd=_cwd,
            api_key=_api_key,
            base_url=_base_url,
            persistent_session=False,
            sandbox_enabled=False,
            setting_sources=["project"],
        )

    def _get_agent_type(self) -> str:
        return "PromptCompiler"

    def _get_mcp_servers(self) -> Optional[Dict[str, Dict[str, Any]]]:
        return None

    def _get_allowed_tools(self) -> List[str]:
        return []

    def _get_output_schema(self) -> Optional[Dict[str, Any]]:
        return None

    async def compile(
        self,
        base_prompt: str,
        category: str,
        mode: str,
        challenge_code: str,
        challenge_name: str,
        points: int,
        target_urls: list[str],
        target_host_ports: str,
        work_dir: str,
        auth_env_keys: list[str],
        recon_data: str,
        prior_knowledge: str,
        user_prompt: str,
        hint: str = "",
    ) -> Optional[str]:
        """将原始题目数据优化为 XML 动态段落片段。

        内部自动查询 RAG 知识库，将相关攻击技术文档注入编译输入，
        LLM 在编译 prompt 时会结合 RAG 知识做 category 纠正和攻击策略制定。

        输入遵循 long-context best practices：长数据（base_prompt、recon）放前面，
        请求指令放最后。

        Args:
            base_prompt: get_brain_prompt() 输出
            category: 题目类型 (web/pwn/crypto/misc)
            mode: 运行模式 (ctf/pentest)
            challenge_code: 题目标识
            challenge_name: 题目名称（用于 RAG 查询）
            points: 分值
            target_urls: 目标 URL 列表
            target_host_ports: 目标 host:port 字符串
            work_dir: 工作目录路径
            auth_env_keys: 容器内可用的认证环境变量名列表
            recon_data: 侦察数据
            prior_knowledge: 历史知识
            user_prompt: 用户提供的题目描述
            hint: 题目 hint（用于 RAG 查询）

        Returns:
            优化后的 XML 动态段落片段，失败时返回 None
        """
        # --- 组装输入：长数据在前，指令在后 ---
        parts: list[str] = []

        # 1. Orchestrator capabilities（最长的参考数据，放最前）
        parts.append(
            "<orchestrator_capabilities>\n"
            f"{base_prompt}\n"
            "</orchestrator_capabilities>"
        )

        # 2. 侦察数据（通常是第二长的数据）
        if recon_data:
            parts.append(
                "<raw_recon_data>\n"
                f"{recon_data}\n"
                "</raw_recon_data>"
            )

        # 2.5 知识库（Agent 通过 kb_search 工具按需搜索，不再自动注入）

        # 3. 历史知识
        if prior_knowledge:
            parts.append(
                "<prior_knowledge_raw>\n"
                f"{prior_knowledge}\n"
                "</prior_knowledge_raw>"
            )

        # 4. 题目元信息（结构化，较短）
        metadata_lines = [
            f"challenge_code: {challenge_code}",
            f"category: {category}",
            f"mode: {mode}",
            f"points: {points}",
        ]
        if target_urls:
            metadata_lines.append(f"target_urls: {', '.join(target_urls)}")
        if target_host_ports:
            metadata_lines.append(f"target_host_ports: {target_host_ports}")
        if work_dir:
            metadata_lines.append(f"work_dir: {work_dir}")
        if auth_env_keys:
            metadata_lines.append(f"auth_env_keys: {', '.join(auth_env_keys)}")

        parts.append(
            "<challenge_metadata_raw>\n"
            + "\n".join(metadata_lines) + "\n"
            "</challenge_metadata_raw>"
        )

        # 5. 比赛提示（代码控制，独立于 user_prompt）
        if hint:
            parts.append(
                "<challenge_hint_raw>\n"
                f"{hint}\n"
                "</challenge_hint_raw>"
            )

        # 6. 用户提供的题目描述
        if user_prompt:
            parts.append(
                "<user_prompt>\n"
                f"{user_prompt}\n"
                "</user_prompt>"
            )

        # 7. 请求指令（放最后，模型注意力最强）
        parts.append(
            "---\n"
            "Based on all the data above, produce the optimized XML fragment for the final prompt. "
            "Output ONLY <compiler_hints>, <reconnaissance>, <prior_knowledge>, "
            "<focus_directives>, <constraints>, and <objective>. "
            "Remember: output ONLY the XML tags, no preamble."
        )

        message = "\n\n".join(parts)

        try:
            result = await self.execute(message)

            if result.get("success") and result.get("response"):
                compiled = result["response"].strip()
                if len(compiled) > 100:
                    log_system_event(
                        "[PromptCompiler] 编译成功",
                        {
                            "input_len": len(message),
                            "compiled_len": len(compiled),
                        },
                    )
                    return compiled

            log_system_event(
                "[PromptCompiler] 输出不可用",
                {"response_len": len(result.get("response", ""))},
                level=logging.WARNING,
            )
            return None

        except Exception as e:
            log_system_event(
                f"[PromptCompiler] 编译失败: {e}",
                level=logging.WARNING,
            )
            return None
