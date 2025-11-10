"""Sentinel Agent 主程序 - 多 Agent 协作模式"""
import uuid
import logging
import asyncio
import os
from langfuse import get_client
from langfuse.langchain import CallbackHandler
from langchain_core.runnables import RunnableConfig
from langchain_openai import ChatOpenAI

from sentinel_agent.core.singleton import get_config_manager
from sentinel_agent.state import PenetrationTesterState
from sentinel_agent.multi_agent_graph import build_multi_agent_graph
from sentinel_agent.model import create_model
from sentinel_agent.common import log_state_update, log_system_event


async def main():
    """主函数 - 多 Agent 协作模式"""
    # ==================== 1. 初始化配置 ====================
    config_manager = get_config_manager()
    config = config_manager.config
    
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
    
    log_system_event(
        "[Advisor LLM] 配置信息",
        {
            "model": siliconflow_model,
            "base_url": siliconflow_base_url,
            "api_key_prefix": siliconflow_api_key[:10] + "..." if siliconflow_api_key else "None"
        }
    )
    
    advisor_llm = ChatOpenAI(
        model=siliconflow_model,
        api_key=siliconflow_api_key,
        base_url=siliconflow_base_url,
        temperature=0.5,  # 稍高的温度，获得更多样化的建议
        max_tokens=2048,
        default_headers={
            "Authorization": f"Bearer {siliconflow_api_key}"
        }
    )
    log_system_event(
        "[Advisor LLM] MiniMax",
        {"model": siliconflow_model, "temperature": 0.5}
    )
    
    # ==================== 4. 预先获取赛题列表（避免浪费 LLM 调用）====================
    from sentinel_agent.tools.competition_api_tools import CompetitionAPIClient
    import time
    
    log_system_event("[*] 预先获取赛题列表...")
    api_client = CompetitionAPIClient()
    
    try:
        challenges_data = api_client.get_challenges()
        all_challenges = challenges_data.get("challenges", [])
        current_phase = challenges_data.get("current_stage", "unknown")
        
        # 过滤掉已解决的题目
        unsolved_challenges = [ch for ch in all_challenges if not ch.get("solved", False)]
        solved_challenges = [ch for ch in all_challenges if ch.get("solved", False)]
        
        # 计算当前总积分
        current_score = sum(ch.get("points", 0) for ch in solved_challenges)
        
        log_system_event(
            f"[✓] 成功获取赛题信息",
            {
                "phase": current_phase,
                "total": len(all_challenges),
                "solved": len(solved_challenges),
                "unsolved": len(unsolved_challenges),
                "current_score": current_score,
                "unsolved_list": [ch.get("challenge_code") for ch in unsolved_challenges]
            }
        )
        
        challenges = unsolved_challenges  # 只保留未解决的题目
        
    except Exception as e:
        log_system_event(
            f"[!] 获取赛题失败: {str(e)}",
            level=logging.ERROR
        )
        challenges = []
        current_phase = "unknown"
        current_score = 0
        solved_challenges = []
    
    # ==================== 5. 初始化 Agent 状态 ====================
    initial_state: PenetrationTesterState = {
        "challenges": challenges if challenges else None,  # 预填充赛题列表（仅未解决的）
        "current_challenge": None,
        "completed_challenges": [],
        "total_challenges": len(challenges) + len(solved_challenges),  # 总题数
        "solved_count": len(solved_challenges),  # 已解答题数
        "unsolved_count": len(challenges),  # 未解答题数
        "hint_used_count": sum(1 for ch in all_challenges if ch.get("hint_viewed", False)),  # 已使用提示的题数
        "attempts_count": 0,
        "current_score": current_score,  # 当前总积分
        "start_time": time.time(),  # 记录开始时间
        "current_phase": current_phase,  # debug/competition
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
        "last_node": "advisor",
        "advisor_suggestion": None,  # 新增：存储顾问建议
    }
    
    # ==================== 6. 构建多 Agent 协作图 ====================
    log_system_event("--- 开始构建多 Agent 协作图 ---")
    app = await build_multi_agent_graph(
        main_llm=main_llm,
        advisor_llm=advisor_llm
    )
    
    # ==================== 7. 配置运行参数 ====================
    thread_id = str(uuid.uuid4())
    runnable_config: RunnableConfig = {
        "configurable": {
            "thread_id": thread_id,
            "configuration": config.__dict__,
        },
        "callbacks": [langfuse_handler],
        "recursion_limit": 100  # CTF 场景需要更多尝试次数
    }
    
    log_system_event(
        "[*] 正在启动 Sentinel Agent（多 Agent 协作模式）", 
        {
            "mode": "multi_agent_competition",
            "thread_id": thread_id,
            "main_agent": "DeepSeek",
            "advisor_agent": "MiniMax"
        }
    )
    
    # ==================== 8. 运行 Agent ====================
    with langfuse.start_as_current_span(name="Sentinel Multi-Agent Run") as span:
        span.update_trace(
            session_id=thread_id,
            tags=["Sentinel", "Multi-Agent", "CTF", "Team-Collaboration"],
            input=initial_state
        )
        
        try:
            # 执行 Agent
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
    
    # ==================== 9. 输出结果 ====================
    log_state_update(
        "=== 多 Agent 协作完成 ===",
        {
            "flag": final_state.get("flag"),
            "total_actions": len(final_state.get("action_history", [])),
            "vulnerabilities_found": len(final_state.get("potential_vulnerabilities", [])),
            "exploits_tried": len(final_state.get("tried_exploits", [])),
            "advisor_consultations": final_state.get("action_history", []).count("advisor"),  # 统计咨询次数
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
