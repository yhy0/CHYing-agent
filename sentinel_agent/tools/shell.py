"""
Shell 命令执行工具
==================

在隔离的 Docker 容器（Kali Linux）中执行渗透测试命令。

核心理念：
- 将原始输出直接返回给 LLM，由 LLM 自主决策
- 不进行预处理和解析，充分发挥 LLM 的理解能力
- 在 Docker 容器内执行，安全隔离
"""
from langchain_core.tools import tool

from sentinel_agent.core.singleton import get_config_manager
from sentinel_agent.core.constants import Timeouts
from sentinel_agent.common import log_tool_event


def _validate_command(command: str) -> tuple[bool, str]:
    """
    验证命令有效性
    
    Args:
        command: 待验证的命令
        
    Returns:
        (是否有效, 错误消息)
    """
    if not command or not command.strip():
        return False, "错误：命令不能为空"
    return True, ""


@tool
async def execute_command(command: str, timeout: int = Timeouts.COMMAND_EXECUTION) -> str:
    """
    在 Docker 容器（Kali Linux）中执行 Shell 命令。
    
    **这是 Agent 的主要工具，用于执行渗透测试命令。**
    
    **支持的工具：**
    - 端口扫描: nmap, masscan
    - 漏洞扫描: nikto, wpscan, sqlmap
    - 目录爆破: gobuster, dirb, ffuf
    - 漏洞利用: metasploit, searchsploit
    - 网络工具: curl, wget, nc
    - 系统工具: ls, cat, grep, find
    
    **示例：**
    ```bash
    # 端口扫描
    nmap -sV -p 192.168.1.10
    
    # 漏洞搜索
    searchsploit nginx 1.21
    
    # SQL 注入测试
    sqlmap -u "http://target/page?id=1" --dbs --batch
    
    # 目录爆破
    gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
    ```
    
    **重要提示：**
    - 命令在隔离的 Docker 容器内执行，与主机完全隔离
    - 原始输出会直接返回，请 LLM 自行分析和决策
    - 默认超时 120 秒，长时间运行的命令请适当调整
    
    Args:
        command: 要执行的完整 Shell 命令字符串
        timeout: 命令执行的超时时间（秒），默认 120 秒
    
    Returns:
        命令执行的原始输出（包含退出码、stdout、stderr）
    """
    # 输入验证
    is_valid, error_msg = _validate_command(command)
    if not is_valid:
        return error_msg
    
    log_tool_event("[Shell] 执行命令", {"command": command, "timeout": timeout})
    
    # 获取执行器并执行
    config_manager = get_config_manager()
    executor = config_manager.executor
    result = executor.execute(command, timeout=timeout)
    
    # 格式化输出（保持原始性，便于 LLM 理解）
    output = f"""Exit Code: {result.exit_code}

--- STDOUT ---
{result.stdout}

--- STDERR ---
{result.stderr}
"""
    
    log_tool_event(
        "[Shell] 命令完成，返回结果给 LLM",
        {
            "exit_code": result.exit_code,
            "stdout_length": len(result.stdout),
            "stderr_length": len(result.stderr),
            "full_output_preview": output if output else "(空)"
        }
    )
    return output
