"""
CHYing Agent - 子代理系统提示词模块
=====================================

包含子代理系统提示词定义：
- Executor Agent：安全执行专家（shell 命令 + Python 脚本）
- C2 Agent：后渗透与 C2 操作专家（Metasploit + tmux）
- Browser Agent：浏览器操作专家（Chrome DevTools）
- Reverse Agent：逆向工程专家（Ghidra + 动态分析）
- Scraper Agent：CTF 平台题目爬取专家
- Flag Submitter Agent：CTF 平台 Flag 提交专家

"""

from chying_agent.agents.executor_agent import EXECUTOR_AGENT_SYSTEM_PROMPT
from chying_agent.agents.c2_agent import C2_AGENT_SYSTEM_PROMPT
from chying_agent.agents.browser_agent import BROWSER_AGENT_SYSTEM_PROMPT
from chying_agent.agents.reverse_agent import REVERSE_AGENT_SYSTEM_PROMPT
from chying_agent.agents.scraper_agent import SCRAPER_AGENT_SYSTEM_PROMPT
from chying_agent.agents.flag_submitter_agent import FLAG_SUBMITTER_AGENT_SYSTEM_PROMPT

__all__ = [
    "EXECUTOR_AGENT_SYSTEM_PROMPT",
    "C2_AGENT_SYSTEM_PROMPT",
    "BROWSER_AGENT_SYSTEM_PROMPT",
    "REVERSE_AGENT_SYSTEM_PROMPT",
    "SCRAPER_AGENT_SYSTEM_PROMPT",
    "FLAG_SUBMITTER_AGENT_SYSTEM_PROMPT",
]
