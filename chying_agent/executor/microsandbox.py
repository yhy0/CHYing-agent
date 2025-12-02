"""
Microsandbox 执行器
===================

使用 Microsandbox 在隔离沙箱中执行 Python 代码。

特点：
- 完全隔离的执行环境
- 支持异步执行
- 自动资源管理
"""

import asyncio
import logging
from typing import Optional
from microsandbox import PythonSandbox

from chying_agent.executor.base import BaseExecutor, ExecutionResult
from chying_agent.common import log_system_event


class MicrosandboxExecutor(BaseExecutor):
    """
    使用 Microsandbox 执行 Python 代码的执行器
    
    主要用途：
    - 执行 LLM 生成的 Python PoC
    - 提供比 Docker Shell 更灵活的能力
    - 完全隔离的安全环境
    """

    def __init__(self, name: str = "CHYing-sandbox"):
        """
        初始化 MicrosandboxExecutor
        
        Args:
            name: 沙箱名称
        """
        self.name = name
        self._sandbox = None
        self._creation_lock = asyncio.Lock()
        
        log_system_event(
            "[Executor] 初始化 MicrosandboxExecutor",
            {"name": name}
        )

    async def _ensure_sandbox(self):
        """确保沙箱已创建（线程安全）"""
        if self._sandbox is None:
            async with self._creation_lock:
                if self._sandbox is None:
                    try:
                        self._sandbox = await PythonSandbox.create(name=self.name).__aenter__()
                        log_system_event(
                            "[Executor] 成功创建 Microsandbox",
                            {"name": self.name}
                        )
                    except Exception as e:
                        log_system_event(
                            "[Executor] 创建 Microsandbox 失败",
                            {"error": str(e)},
                            level=logging.ERROR
                        )
                        raise ConnectionError(f"无法创建 Microsandbox: {str(e)}") from e

    async def execute_async(self, command: str, timeout: int = 120) -> ExecutionResult:
        """
        异步执行 Python 代码
        
        Args:
            command: Python 代码字符串
            timeout: 超时时间（秒）

        Returns:
            ExecutionResult 实例
        """
        try:
            await self._ensure_sandbox()
            
            # 在沙箱中执行代码
            exec_result = await asyncio.wait_for(
                self._sandbox.run(command),
                timeout=timeout
            )
            
            # 获取输出
            output = await exec_result.output()
            output_str = output if output else ""
            
            # 记录执行结果
            log_system_event(
                "[Executor] Microsandbox 执行结果",
                {
                    "exit_code": 0,
                    "output_preview": output_str if output_str else "(空)",
                    "output_length": len(output_str)
                }
            )
            
            return ExecutionResult(
                exit_code=0,
                stdout=output_str,
                stderr="",
                command=command,
            )
        except asyncio.TimeoutError:
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"命令执行超时（{timeout}秒）",
                command=command,
            )
        except Exception as e:
            log_system_event(
                "[Executor] 在 Microsandbox 中执行命令时发生错误",
                {"error": str(e), "command": command},
                level=logging.ERROR
            )
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"在 Microsandbox 中执行命令时发生错误: {str(e)}",
                command=command,
            )

    def execute(self, command: str, timeout: int = 120) -> ExecutionResult:
        """
        同步接口（兼容已运行的事件循环）
        
        Args:
            command: Python 代码字符串
            timeout: 超时时间（秒）

        Returns:
            ExecutionResult 实例
        """
        try:
            # 尝试获取当前事件循环
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # 如果事件循环已在运行，使用 run_coroutine_threadsafe
                import concurrent.futures
                future = asyncio.run_coroutine_threadsafe(
                    self.execute_async(command, timeout), 
                    loop
                )
                return future.result(timeout=timeout + 5)
            else:
                # 事件循环未运行，直接运行
                return loop.run_until_complete(self.execute_async(command, timeout))
        except RuntimeError:
            # 没有事件循环，创建新的
            return asyncio.run(self.execute_async(command, timeout))

    async def cleanup(self):
        """异步清理沙箱资源"""
        if self._sandbox is not None:
            try:
                await self._sandbox.__aexit__(None, None, None)
                self._sandbox = None
                log_system_event("[Executor] 成功清理 Microsandbox 资源")
            except Exception as e:
                log_system_event(
                    "[Executor] 清理 Microsandbox 时发生错误",
                    {"error": str(e)},
                    level=logging.WARNING
                )

    def __del__(self):
        """析构函数：记录清理提示"""
        if self._sandbox is not None:
            log_system_event(
                "[Executor] Microsandbox 实例销毁，请确保调用 cleanup() 清理资源",
                level=logging.INFO
            )
