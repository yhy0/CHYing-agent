"""
Python PoC 执行工具
===================

在隔离的 Microsandbox 沙箱中执行 LLM 生成的 Python PoC 代码。

核心理念：
- 由 LLM 自主生成和执行 Python PoC
- 提供比 Shell 命令更灵活的能力（HTTP 请求、数据处理等）
- 在完全隔离的沙箱中执行，安全可靠
"""
from langchain_core.tools import tool

from sentinel_agent.core.constants import Timeouts
from sentinel_agent.common import log_tool_event


def _validate_code(code: str) -> tuple[bool, str]:
    """
    验证代码有效性（包括语法检查）

    Args:
        code: 待验证的 Python 代码

    Returns:
        (是否有效, 错误消息)
    """
    if not code or not code.strip():
        return False, "错误：代码不能为空"

    # 语法检查
    try:
        compile(code, '<string>', 'exec')
    except SyntaxError as e:
        return False, f"语法错误（第 {e.lineno} 行）: {e.msg}\n提示：请检查缩进是否正确（使用 4 个空格）"
    except IndentationError as e:
        return False, f"缩进错误（第 {e.lineno} 行）: {e.msg}\n提示：Python 代码必须使用一致的缩进（推荐 4 个空格）"
    except Exception as e:
        return False, f"代码验证失败: {str(e)}"

    return True, ""


@tool
async def execute_python_poc(code: str, timeout: int = Timeouts.COMMAND_EXECUTION) -> str:
    """
    在隔离的 Python 沙箱（Microsandbox）中执行 Python PoC 代码。
    
    **用途：**
    - 执行 LLM 生成的漏洞验证代码（PoC）
    - HTTP 请求和 API 测试
    - 数据处理和解析
    - 自定义漏洞利用脚本
    
    **示例 1 - SQL 注入 PoC：**
    ```python
    import requests
    
    target = "http://192.168.1.100/login"
    payload = "admin' OR '1'='1"
    
    resp = requests.post(target, data={'user': payload, 'pass': 'test'})
    if 'welcome' in resp.text.lower():
        print('✓ SQL 注入成功！')
        print(f'Response: {resp.text}')
    ```
    
    **示例 2 - XSS 检测：**
    ```python
    import requests
    
    target = "http://192.168.1.100/search"
    payload = "<script>alert('XSS')</script>"
    
    resp = requests.get(target, params={'q': payload})
    if payload in resp.text:
        print('✓ 存在反射型 XSS！')
    ```
    
    **示例 3 - API 枚举：**
    ```python
    import requests
    
    base_url = "http://192.168.1.100/api"
    endpoints = ['/users', '/admin', '/config', '/debug']
    
    for ep in endpoints:
        resp = requests.get(base_url + ep)
        print(f'{ep}: {resp.status_code}')
        if resp.status_code == 200:
            print(f'  ✓ 可访问！数据: {resp.text}')
    ```
    
    **注意：**
    - 需要配置 SANDBOX_ENABLED=true
    - 需要启动 Microsandbox 服务器（docker run -d -p 5555:5555 microsandbox/microsandbox-server）
    - 代码在完全隔离的沙箱中执行，安全可靠
    - 支持标准 Python 库（requests, json, re, base64 等）
    
    Args:
        code: 要执行的 Python 代码字符串。
        timeout: 代码执行的超时时间（秒），默认为120秒。
    
    Returns:
        包含执行结果的字符串（stdout、stderr 和退出码）。
    """
    # 输入验证（包括语法检查）
    is_valid, error_msg = _validate_code(code)
    if not is_valid:
        log_tool_event("[Python PoC] 代码验证失败", {"error": error_msg})
        return f"❌ {error_msg}\n\n请修复代码后重试。"

    log_tool_event(f"[Python PoC] 执行代码", {"code_length": len(code), "timeout": timeout})
    
    # 使用工厂函数获取 Python 执行器（Microsandbox）
    from sentinel_agent.core.singleton import get_config_manager
    from sentinel_agent.executor.factory import get_python_executor
    from sentinel_agent.executor.microsandbox import MicrosandboxExecutor
    
    config_manager = get_config_manager()
    executor = get_python_executor(config_manager.config)
    
    # 如果是 MicrosandboxExecutor，直接调用异步方法
    if isinstance(executor, MicrosandboxExecutor):
        result = await executor.execute_async(code, timeout=timeout)
    else:
        # 其他执行器使用同步方法
        result = executor.execute(code, timeout=timeout)
    
    output = f"""Exit Code: {result.exit_code}
--- OUTPUT ---
{result.stdout}
--- ERRORS ---
{result.stderr}
"""
    
    log_tool_event(
        "[Python PoC] 执行完成，返回结果给 LLM",
        {
            "exit_code": result.exit_code,
            "stdout_length": len(result.stdout),
            "stderr_length": len(result.stderr),
            "full_output_preview": output if output else "(空)"
        }
    )
    return output
