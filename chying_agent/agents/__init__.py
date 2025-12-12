"""
CHYing Agent - 多 Agent 系统提示词模块
=====================================

包含三层架构的 Agent 系统提示词定义：
- 规划层：Advisor Agent + Main Agent
- 执行层：PoC Agent + Docker Agent
"""

from chying_agent.agents.advisor import ADVISOR_SYSTEM_PROMPT
from chying_agent.agents.main_agent import MAIN_AGENT_SYSTEM_PROMPT
from chying_agent.agents.poc_agent import POC_AGENT_SYSTEM_PROMPT
from chying_agent.agents.docker_agent import DOCKER_AGENT_SYSTEM_PROMPT

__all__ = [
    "ADVISOR_SYSTEM_PROMPT",
    "MAIN_AGENT_SYSTEM_PROMPT",
    "POC_AGENT_SYSTEM_PROMPT",
    "DOCKER_AGENT_SYSTEM_PROMPT",
]
