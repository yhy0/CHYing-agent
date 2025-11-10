"""Sentinel Agent 主程序 - 持续运行的多 Agent 并发解题模式

架构：
- 持续运行，不自动退出
- 每 10 分钟定时拉取新题目
- 为每道题创建独立的 Agent 实例（异步并发）
- 动态管理解题任务队列（新题自动加入，完成自动清理）
- 实时汇总得分和进度

适用场景：
- 题目分批发布（非一次性发放）
- 需要长时间运行
- 题目之间无依赖关系
- 服务器资源充足
"""
import uuid
import logging
import asyncio
import os
import time
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
from langfuse import get_client
from langfuse.langchain import CallbackHandler
from langchain_core.runnables import RunnableConfig
from langchain_openai import ChatOpenAI

from sentinel_agent.core.singleton import get_config_manager
from sentinel_agent.state import PenetrationTesterState
from sentinel_agent.graph import build_multi_agent_graph
from sentinel_agent.model import create_model
from sentinel_agent.common import log_state_update, log_system_event


# ==================== 并发控制 ====================
# ⭐ 全局并发限制器：控制同时运行的最大任务数（避免速率限制）
MAX_CONCURRENT_TASKS = int(os.getenv("MAX_CONCURRENT_TASKS", "3"))  # 默认最多同时 3 个任务
concurrent_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)

log_system_event(
    f"[并发控制] 最大并发任务数: {MAX_CONCURRENT_TASKS}",
    {"可通过环境变量 MAX_CONCURRENT_TASKS 调整"}
)


# ==================== 全局任务管理器 ====================
@dataclass
class TaskStatus:
    """任务状态"""
    challenge_code: str
    task: asyncio.Task
    start_time: float
    retry_count: int = 0
    
class ChallengeTaskManager:
    """挑战任务管理器 - 负责动态管理解题任务"""
    
    def __init__(self):
        self.active_tasks: Dict[str, TaskStatus] = {}  # challenge_code -> TaskStatus
        self.completed_challenges: Set[str] = set()  # 已完成的题目代码
        self.failed_challenges: Dict[str, int] = {}  # challenge_code -> 失败次数
        self.lock = asyncio.Lock()  # 线程安全锁
        
    async def add_task(self, challenge_code: str, task: asyncio.Task) -> bool:
        """添加新任务到管理器"""
        async with self.lock:
            if challenge_code in self.active_tasks:
                log_system_event(
                    f"[任务管理器] 任务已存在，跳过: {challenge_code}",
                    level=logging.WARNING
                )
                return False
            
            if challenge_code in self.completed_challenges:
                log_system_event(
                    f"[任务管理器] 题目已完成，跳过: {challenge_code}",
                    level=logging.INFO
                )
                return False
            
            self.active_tasks[challenge_code] = TaskStatus(
                challenge_code=challenge_code,
                task=task,
                start_time=time.time(),
                retry_count=self.failed_challenges.get(challenge_code, 0)
            )
            log_system_event(
                f"[任务管理器] 添加任务: {challenge_code} (重试次数: {self.failed_challenges.get(challenge_code, 0)})"
            )
            return True
    
    async def remove_task(self, challenge_code: str, success: bool = False):
        """移除任务"""
        async with self.lock:
            if challenge_code in self.active_tasks:
                task_status = self.active_tasks.pop(challenge_code)
                elapsed = time.time() - task_status.start_time
                
                if success:
                    self.completed_challenges.add(challenge_code)
                    if challenge_code in self.failed_challenges:
                        del self.failed_challenges[challenge_code]
                    log_system_event(
                        f"[任务管理器] ✅ 任务完成: {challenge_code} (耗时: {elapsed:.1f}s)"
                    )
                else:
                    self.failed_challenges[challenge_code] = self.failed_challenges.get(challenge_code, 0) + 1
                    log_system_event(
                        f"[任务管理器] ❌ 任务失败: {challenge_code} (失败次数: {self.failed_challenges[challenge_code]})"
                    )
    
    async def get_status(self) -> Dict:
        """获取当前状态"""
        async with self.lock:
            return {
                "active_count": len(self.active_tasks),
                "completed_count": len(self.completed_challenges),
                "failed_count": len(self.failed_challenges),
                "active_tasks": list(self.active_tasks.keys()),
                "completed_tasks": list(self.completed_challenges),
                "failed_tasks": dict(self.failed_challenges)
            }
    
    async def cleanup_finished_tasks(self):
        """清理已完成的任务"""
        async with self.lock:
            to_remove = []
            for code, status in self.active_tasks.items():
                if status.task.done():
                    to_remove.append(code)
            
            for code in to_remove:
                # 不在这里移除，让任务回调自己处理
                pass
    
    def is_completed(self, challenge_code: str) -> bool:
        """检查题目是否已完成"""
        return challenge_code in self.completed_challenges
    
    def is_active(self, challenge_code: str) -> bool:
        """检查题目是否正在解决"""
        return challenge_code in self.active_tasks


# 全局任务管理器实例
task_manager = ChallengeTaskManager()


async def solve_single_challenge(
    challenge: Dict,
    main_llm,
    advisor_llm,
    config,
    langfuse_handler,
) -> Dict:
    """
    解决单个题目（完全异常隔离，单题失败不影响其他题）
    
    Args:
        challenge: 题目信息
        main_llm: 主 LLM
        advisor_llm: 顾问 LLM
        config: 配置
        langfuse_handler: Langfuse 回调
        
    Returns:
        解题结果 {code, flag, score, attempts, success}
        
    CRITICAL: 此函数保证任何异常都不会向外传播，始终返回结果字典
    """
    challenge_code = challenge.get("challenge_code", "unknown")
    difficulty = challenge.get("difficulty", "unknown")
    points = challenge.get("points", 0)
    
    # 获取当前任务管理器状态
    status = await task_manager.get_status()
    
    log_system_event(
        f"[解题] 开始攻击: {challenge_code}",
        {
            "difficulty": difficulty, 
            "points": points,
            "active_tasks": status['active_count'],
            "completed": status['completed_count']
        }
    )
    
    # 为每个题目创建独立的状态
    initial_state: PenetrationTesterState = {
        "challenges": [challenge],  # 只包含当前题目
        "current_challenge": challenge,  # 直接开始攻击
        "completed_challenges": [],
        "total_challenges": 1,
        "solved_count": 0,
        "unsolved_count": 1,
        "hint_used_count": 0,
        "attempts_count": 0,
        "current_score": 0,
        "start_time": time.time(),
        "current_phase": "competition",
        "open_ports": [],
        "service_info": {},
        "potential_vulnerabilities": [],
        "tried_exploits": [],
        "last_exploit_status": None,
        "last_action_output": "",
        "flag": None,
        "is_finished": False,
        "action_history": [],
        "evidence_chain_ids": [],
        "current_snapshot_id": f"challenge_{challenge_code}",
        "last_node": "advisor",
        "advisor_suggestion": None,
        # ⭐ 智能路由控制字段
        "consecutive_failures": 0,
        "last_action_type": None,
        "request_advisor_help": False,
    }

    # ==================== 自动信息收集（在 Agent 启动前） ====================
    target_info = challenge.get("target_info", {})
    target_ip = target_info.get("ip")
    target_ports = target_info.get("port", [])

    if target_ip and target_ports:
        # 使用第一个端口进行侦察（通常是 HTTP 端口）
        target_port = target_ports[0] if isinstance(target_ports, list) else target_ports

        log_system_event(
            f"[自动侦察] 开始收集目标信息: {target_ip}:{target_port}",
            {"challenge_code": challenge_code}
        )

        try:
            from sentinel_agent.utils.recon import auto_recon_web_target, format_recon_result_for_llm
            from langchain_core.messages import HumanMessage

            # 执行自动侦察（提高超时时间到 30 秒）
            recon_result = auto_recon_web_target(target_ip, target_port, timeout=30)

            # 将侦察结果格式化并注入到初始状态
            recon_summary = format_recon_result_for_llm(recon_result)

            # 🔧 修复：将侦察结果注入到 messages 中，而不是 last_action_output
            # 这样 Advisor 和 Main Agent 都能在消息历史中看到完整的侦察结果
            initial_state["messages"] = [
                HumanMessage(content=f"🔍 系统自动侦察结果：\n\n{recon_summary}")
            ]

            # 同时添加到 action_history 用于统计
            initial_state["action_history"].append(
                f"[自动侦察] 已完成目标 {target_ip}:{target_port} 的基础信息收集"
            )

            log_system_event(
                f"[自动侦察] ✅ 信息收集完成",
                {
                    "success": recon_result["success"],
                    "status_code": recon_result.get("status_code"),
                    "content_length": recon_result.get("html_length", 0)
                }
            )

        except Exception as recon_error:
            log_system_event(
                f"[自动侦察] ⚠️ 侦察失败: {str(recon_error)}",
                level=logging.WARNING
            )
            # 侦察失败不影响后续流程，继续执行
    else:
        log_system_event(
            f"[自动侦察] ⚠️ 无法获取目标信息，跳过自动侦察",
            {"challenge": challenge},
            level=logging.WARNING
        )
    # ==================== 自动信息收集结束 ====================

    # 构建独立的 Agent 图
    app = await build_multi_agent_graph(
        main_llm=main_llm,
        advisor_llm=advisor_llm
    )
    
    # 配置运行参数
    from sentinel_agent.core.constants import AgentConfig

    thread_id = str(uuid.uuid4())
    recursion_limit = AgentConfig.get_recursion_limit()
    runnable_config: RunnableConfig = {
        "configurable": {
            "thread_id": thread_id,
            "configuration": config.__dict__,
        },
        "callbacks": [langfuse_handler],
        "recursion_limit": recursion_limit  # 从环境变量读取
    }

    # 最外层异常保护：确保此函数永远不会抛出异常
    try:
        start_time = time.time()

        # ⭐ 执行 Agent（使用并发限制器 + 超时保护）
        task_timeout = AgentConfig.get_single_task_timeout()
        try:
            # 使用并发限制器，避免同时运行过多任务导致速率限制
            async with concurrent_semaphore:
                log_system_event(
                    f"[并发控制] 获取执行槽位: {challenge_code}",
                    {"活跃槽位": f"{MAX_CONCURRENT_TASKS - concurrent_semaphore._value}/{MAX_CONCURRENT_TASKS}"}
                )
                
                async with asyncio.timeout(task_timeout):
                    final_state = await app.ainvoke(initial_state, runnable_config)
        except asyncio.TimeoutError:
            log_system_event(
                f"[解题] ⏱️ 超时: {challenge_code}（{task_timeout}秒）",
                level=logging.WARNING
            )
            await task_manager.remove_task(challenge_code, success=False)
            return {
                "code": challenge_code,
                "flag": None,
                "score": 0,
                "attempts": 0,
                "success": False,
                "timeout": True,
                "elapsed_time": task_timeout
            }
        except KeyboardInterrupt:
            # 允许用户手动中断
            log_system_event(
                f"[解题] 🛑 用户中断: {challenge_code}",
                level=logging.WARNING
            )
            raise  # KeyboardInterrupt 应该向上传播
        except Exception as agent_error:
            # Agent 执行异常（网络、API、LLM 错误等）
            log_system_event(
                f"[解题] ⚠️ Agent 执行异常: {challenge_code} - {str(agent_error)}",
                level=logging.ERROR
            )
            await task_manager.remove_task(challenge_code, success=False)
            return {
                "code": challenge_code,
                "flag": None,
                "score": 0,
                "attempts": 0,
                "success": False,
                "error": f"agent_error: {str(agent_error)}",
                "elapsed_time": time.time() - start_time
            }
        
        elapsed_time = time.time() - start_time
        flag = final_state.get("flag")
        attempts = len(final_state.get("action_history", []))
        
        if flag:
            log_system_event(
                f"[解题] ✅ 成功: {challenge_code}",
                {
                    "flag": flag,
                    "attempts": attempts,
                    "elapsed": f"{elapsed_time:.1f}s"
                }
            )
            await task_manager.remove_task(challenge_code, success=True)
            return {
                "code": challenge_code,
                "flag": flag,
                "score": points,  # 假设满分
                "attempts": attempts,
                "success": True,
                "elapsed_time": elapsed_time
            }
        else:
            log_system_event(
                f"[解题] ❌ 失败: {challenge_code}",
                {
                    "attempts": attempts,
                    "elapsed": f"{elapsed_time:.1f}s"
                }
            )
            await task_manager.remove_task(challenge_code, success=False)
            return {
                "code": challenge_code,
                "flag": None,
                "score": 0,
                "attempts": attempts,
                "success": False,
                "elapsed_time": elapsed_time
            }
    
    except KeyboardInterrupt:
        # 允许 Ctrl+C 中断整个程序
        log_system_event(
            f"[解题] 🛑 用户中断",
            level=logging.WARNING
        )
        raise
    except Exception as outer_error:
        # 最外层兜底：捕获所有未预期的异常（包括 Agent 构建失败等）
        log_system_event(
            f"[解题] 🚨 严重异常: {challenge_code} - {str(outer_error)}",
            level=logging.CRITICAL
        )
        await task_manager.remove_task(challenge_code, success=False)
        return {
            "code": challenge_code,
            "flag": None,
            "score": 0,
            "attempts": 0,
            "success": False,
            "error": f"critical_error: {str(outer_error)}",
            "elapsed_time": 0
        }


async def fetch_new_challenges(api_client) -> List[Dict]:
    """获取新的题目列表"""
    try:
        challenges_data = api_client.get_challenges()
        all_challenges = challenges_data.get("challenges", [])

        # 检查是否允许重新攻击已解决的题目（调试模式）
        import os
        allow_resolved = os.getenv("DEBUG_ALLOW_RESOLVED", "false").lower() == "true"

        if allow_resolved:
            log_system_event(
                "[调试模式] 允许重新攻击已解决的题目",
                {"total_challenges": len(all_challenges)}
            )
            return all_challenges
        else:
            # 过滤掉已解决的题目（从 API 返回的 solved 字段）
            unsolved_challenges = [ch for ch in all_challenges if not ch.get("solved", False)]
            log_system_event(
                "[正式模式] 仅攻击未解决的题目",
                {
                    "total": len(all_challenges),
                    "unsolved": len(unsolved_challenges),
                    "solved": len(all_challenges) - len(unsolved_challenges)
                }
            )
            return unsolved_challenges
    except Exception as e:
        log_system_event(
            f"[!] 获取赛题失败: {str(e)}",
            level=logging.ERROR
        )
        return []


async def start_challenge_task(
    challenge: Dict,
    main_llm,
    advisor_llm,
    config,
    langfuse_handler
) -> bool:
    """启动一个挑战任务"""
    challenge_code = challenge.get("challenge_code", "unknown")
    
    # 检查是否已完成或正在执行
    if task_manager.is_completed(challenge_code):
        return False
    
    if task_manager.is_active(challenge_code):
        return False
    
    # 创建异步任务
    task = asyncio.create_task(
        solve_single_challenge(
            challenge=challenge,
            main_llm=main_llm,
            advisor_llm=advisor_llm,
            config=config,
            langfuse_handler=langfuse_handler
        )
    )
    
    # 添加到任务管理器
    success = await task_manager.add_task(challenge_code, task)
    return success


async def periodic_fetch_challenges(
    api_client,
    main_llm,
    advisor_llm,
    config,
    langfuse_handler,
    interval_seconds: int = 600  # 默认 10 分钟
):
    """定时拉取新题目的后台任务"""
    log_system_event(
        f"[定时任务] 启动定时拉取任务（每 {interval_seconds//60} 分钟）"
    )
    
    while True:
        try:
            # 获取当前所有未解决的题目
            unsolved_challenges = await fetch_new_challenges(api_client)
            
            if not unsolved_challenges:
                log_system_event(
                    "[定时任务] 没有找到新题目或所有题目已完成"
                )
            else:
                # 尝试为每个未解决的题目创建任务（如果尚未创建）
                new_task_count = 0
                for challenge in unsolved_challenges:
                    challenge_code = challenge.get("challenge_code", "unknown")
                    
                    # 只为新题目创建任务
                    if await start_challenge_task(
                        challenge=challenge,
                        main_llm=main_llm,
                        advisor_llm=advisor_llm,
                        config=config,
                        langfuse_handler=langfuse_handler
                    ):
                        new_task_count += 1
                        log_system_event(
                            f"[定时任务] 🆕 发现新题目: {challenge_code}"
                        )
                
                if new_task_count > 0:
                    log_system_event(
                        f"[定时任务] 本轮新增 {new_task_count} 个解题任务"
                    )
            
            # 打印当前状态
            status = await task_manager.get_status()
            log_system_event(
                f"[定时任务] 当前状态",
                {
                    "活跃任务": status['active_count'],
                    "已完成": status['completed_count'],
                    "失败": status['failed_count']
                }
            )
            
            # 等待下一次拉取
            await asyncio.sleep(interval_seconds)
            
        except asyncio.CancelledError:
            log_system_event("[定时任务] 收到停止信号，退出定时任务")
            break
        except Exception as e:
            log_system_event(
                f"[定时任务] 发生错误: {str(e)}，将在下一轮重试",
                level=logging.ERROR
            )
            await asyncio.sleep(interval_seconds)


async def status_monitor(interval_seconds: int = 300):
    """状态监控任务 - 每 5 分钟打印一次状态"""
    log_system_event(
        f"[状态监控] 启动状态监控任务（每 {interval_seconds//60} 分钟）"
    )
    
    while True:
        try:
            await asyncio.sleep(interval_seconds)
            
            status = await task_manager.get_status()
            
            print("\n" + "="*80)
            print("📊 系统状态汇总")
            print("="*80)
            print(f"活跃任务: {status['active_count']} 个")
            print(f"已完成: {status['completed_count']} 个")
            print(f"失败: {status['failed_count']} 个")
            
            if status['active_tasks']:
                print(f"\n🔄 正在解题: {', '.join(status['active_tasks'])}")
            
            if status['completed_tasks']:
                print(f"\n✅ 已完成: {', '.join(status['completed_tasks'])}")
            
            if status['failed_tasks']:
                print("\n❌ 失败题目:")
                for code, count in status['failed_tasks'].items():
                    print(f"  - {code}: {count} 次失败")
            
            print("="*80 + "\n")
            
        except asyncio.CancelledError:
            log_system_event("[状态监控] 收到停止信号，退出监控任务")
            break
        except Exception as e:
            log_system_event(
                f"[状态监控] 发生错误: {str(e)}",
                level=logging.ERROR
            )


async def main():
    """主函数 - 持续运行的并发解题模式"""
    # ==================== 1. 初始化配置 ====================
    config_manager = get_config_manager()
    config = config_manager.config
    
    log_system_event(
        "=" * 80 + "\n" +
        "🚀 Sentinel Agent 持续运行模式启动\n" +
        "=" * 80
    )
    
    # ==================== 2. 初始化 Langfuse ====================
    langfuse = get_client()
    langfuse_handler = CallbackHandler()
    
    # ==================== 3. 创建双 LLM 模型 ====================
    # 主 Agent：DeepSeek
    main_llm = create_model(config=config)
    log_system_event(
        "[Main LLM] DeepSeek",
        {"model": config.llm_model_name}
    )
    
    # 顾问 Agent：MiniMax（通过 SiliconFlow）
    siliconflow_api_key = os.getenv("SILICONFLOW_API_KEY")
    siliconflow_base_url = os.getenv("SILICONFLOW_BASE_URL", "https://api.siliconflow.com/v1")
    siliconflow_model = os.getenv("SILICONFLOW_MODEL", "MiniMaxAI/MiniMax-M2")
    
    # 验证配置
    if not siliconflow_api_key:
        raise ValueError(
            "配置错误: 未找到 SILICONFLOW_API_KEY。\n"
            "请在 .env 中添加:\n"
            "SILICONFLOW_API_KEY=\"your-api-key-here\""
        )
    
    advisor_llm = ChatOpenAI(
        model=siliconflow_model,
        api_key=siliconflow_api_key,
        base_url=siliconflow_base_url,
        temperature=0.5,
        max_tokens=2048,
        default_headers={
            "Authorization": f"Bearer {siliconflow_api_key}"
        }
    )
    log_system_event(
        "[Advisor LLM] MiniMax",
        {"model": siliconflow_model, "temperature": 0.5}
    )
    
    # ==================== 4. 初始化 API 客户端 ====================
    from sentinel_agent.tools.competition_api_tools import CompetitionAPIClient
    
    api_client = CompetitionAPIClient()
    log_system_event("[✓] API 客户端初始化完成")
    
    # ==================== 5. 首次拉取题目并启动初始任务 ====================
    log_system_event("[*] 首次拉取题目...")
    unsolved_challenges = await fetch_new_challenges(api_client)
    
    if unsolved_challenges:
        log_system_event(
            f"[✓] 发现 {len(unsolved_challenges)} 道未解决题目",
            {"challenges": [ch.get("challenge_code") for ch in unsolved_challenges]}
        )
        
        # 为每道题创建任务
        for challenge in unsolved_challenges:
            await start_challenge_task(
                challenge=challenge,
                main_llm=main_llm,
                advisor_llm=advisor_llm,
                config=config,
                langfuse_handler=langfuse_handler
            )
    else:
        log_system_event("[!] 没有发现未解决的题目")
    
    # ==================== 6. 启动后台任务 ====================
    # 定时拉取新题目的任务（每 10 分钟）
    fetch_interval = int(os.getenv("FETCH_INTERVAL_SECONDS", "600"))  # 默认 10 分钟
    fetch_task = asyncio.create_task(
        periodic_fetch_challenges(
            api_client=api_client,
            main_llm=main_llm,
            advisor_llm=advisor_llm,
            config=config,
            langfuse_handler=langfuse_handler,
            interval_seconds=fetch_interval
        )
    )
    
    # 状态监控任务（每 5 分钟）
    monitor_interval = int(os.getenv("MONITOR_INTERVAL_SECONDS", "300"))  # 默认 5 分钟
    monitor_task = asyncio.create_task(
        status_monitor(interval_seconds=monitor_interval)
    )
    
    log_system_event(
        "[✓] 后台任务启动完成",
        {
            "定时拉取间隔": f"{fetch_interval//60} 分钟",
            "状态监控间隔": f"{monitor_interval//60} 分钟"
        }
    )
    
    # ==================== 7. 持续运行 ====================
    log_system_event(
        "\n" + "="*80 + "\n" +
        "✅ 系统正在运行中...\n" +
        "- 按 Ctrl+C 可以优雅退出\n" +
        "- 系统会自动拉取新题目并创建解题任务\n" +
        "- 解题完成后会自动清理任务\n" +
        "="*80
    )
    
    try:
        # 等待所有后台任务（无限期运行）
        await asyncio.gather(fetch_task, monitor_task)
    except KeyboardInterrupt:
        log_system_event(
            "\n🛑 收到中断信号，正在优雅退出...",
            level=logging.WARNING
        )
        
        # 取消后台任务
        fetch_task.cancel()
        monitor_task.cancel()
        
        # 等待后台任务完成取消
        try:
            await asyncio.gather(fetch_task, monitor_task, return_exceptions=True)
        except Exception:
            pass
        
        # 打印最终状态
        final_status = await task_manager.get_status()
        print("\n" + "="*80)
        print("📊 最终状态汇总")
        print("="*80)
        print(f"已完成: {final_status['completed_count']} 个")
        print(f"失败: {final_status['failed_count']} 个")
        print(f"未完成: {final_status['active_count']} 个")
        
        if final_status['completed_tasks']:
            print(f"\n✅ 已完成题目: {', '.join(final_status['completed_tasks'])}")
        
        if final_status['active_tasks']:
            print(f"\n⚠️ 未完成题目: {', '.join(final_status['active_tasks'])}")
        
        print("="*80)
        
        log_system_event("👋 程序已退出")


if __name__ == "__main__":
    asyncio.run(main())
