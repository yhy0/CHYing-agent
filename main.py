"""Sentinel Agent 主程序"""
import uuid
import logging
import asyncio
from langfuse import get_client
from langfuse.langchain import CallbackHandler
from langchain_core.runnables import RunnableConfig

from sentinel_agent.core.singleton import get_config_manager
from sentinel_agent.state import PenetrationTesterState
from sentinel_agent.graph import build_graph
from sentinel_agent.model import create_model
from sentinel_agent.common import log_state_update, log_system_event


async def main():
    """主函数"""
    # ==================== 1. 初始化配置 ====================
    # 注意：load_dotenv() 已在 load_agent_config() 中调用，无需重复
    
    # 使用单例模式获取配置
    config_manager = get_config_manager()
    config = config_manager.config
    
    # ==================== 2. 初始化 Langfuse ====================
    langfuse = get_client()
    langfuse_handler = CallbackHandler()
    
    # ==================== 3. 创建 LLM 模型 ====================
    llm_model = create_model(config=config)
    
    # ==================== 4. 初始化 Agent 状态 ====================
    initial_state: PenetrationTesterState = {
        "challenges": None,  # 将从 API 获取
        "current_challenge": None,
        "completed_challenges": [],
        "total_challenges": 0,
        "solved_count": 0,
        "unsolved_count": 0,
        "hint_used_count": 0,
        "attempts_count": 0,
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
        "current_snapshot_id": "initial_snapshot",
        "last_node": "recon"
    }
    
    # ==================== 5. 构建 LangGraph ====================
    log_system_event("--- 开始构建 LangGraph ---")
    app = await build_graph(llm_model=llm_model)
    
    # ==================== 6. 配置运行参数 ====================
    thread_id = str(uuid.uuid4())
    runnable_config: RunnableConfig = {
        "configurable": {
            "thread_id": thread_id,
            "configuration": config.__dict__,
        },
        "callbacks": [langfuse_handler],
        "recursion_limit": 100  # CTF 场景需要更多尝试次数（从默认 25 增加到 100）
    }
    
    log_system_event(
        "[*] 正在启动 Sentinel Agent", 
        {
            "mode": "competition",
            "thread_id": thread_id
        }
    )
    
    # ==================== 7. 运行 Agent ====================
    with langfuse.start_as_current_span(name="Sentinel Agent Run") as span:
        span.update_trace(
            session_id=thread_id,
            tags=["Sentinel", "APT", "Security Research", "v2-refactored"],
            input=initial_state
        )
        
        try:
            # 执行 Agent（支持断点恢复）
            final_state = await app.ainvoke(initial_state, runnable_config)
            
            span.update_trace(
                output=final_state,
                metadata={"status": "completed"}
            )
            
        except Exception as e:
            log_system_event(
                f"[!] Agent 运行出错: {str(e)}", 
                level=logging.ERROR
            )
            span.update_trace(
                output={"error": str(e)},
                metadata={"status": "failed"}
            )
            raise
    
    # ==================== 8. 输出结果 ====================
    log_state_update(
        "=== Agent 运行完成 ===",
        {
            "flag": final_state.get("flag"),
            "total_actions": len(final_state.get("action_history", [])),
            "vulnerabilities_found": len(final_state.get("potential_vulnerabilities", [])),
            "exploits_tried": len(final_state.get("tried_exploits", [])),
        }
    )
    
    # 打印执行历史
    print("\n" + "="*60)
    print("执行历史：")
    print("="*60)
    for i, action in enumerate(final_state.get("action_history", []), 1):
        print(f"{i}. {action}")
    
    if final_state.get("flag"):
        print("\n" + "="*60)
        print(f"🎯 成功获取 FLAG: {final_state['flag']}")
        print("="*60)
    else:
        print("\n" + "="*60)
        print("⚠️  未能获取 FLAG，请查看日志分析原因。")
        print("="*60)


if __name__ == "__main__":
    asyncio.run(main())
