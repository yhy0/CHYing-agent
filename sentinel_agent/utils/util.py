from sentinel_agent.common import log_state_update, log_system_event
from typing import List, Dict
import logging
import asyncio

async def fetch_new_challenges(api_client) -> List[Dict]:
    """获取新的题目列表"""
    try:
        challenges_data = api_client.get_challenges()
        all_challenges = challenges_data.get("challenges", [])

        # 检查是否允许重新攻击已解决的题目（调试模式）
        import os
        allow_resolved = os.getenv("DEBUG_ALLOW_RESOLVED", "false").lower() == "true"

        if allow_resolved:
            # 在调试模式下，将所有题目的 solved 状态改为 False（unsolved）
            original_count = len(all_challenges)
            solved_count = sum(1 for ch in all_challenges if ch.get("solved", False))

            unsolved_challenges = []
            for i in range(1):
                for ch in all_challenges[:original_count]:
                    challenge_copy = ch.copy()
                    # ⭐ 关键修改：强制将 solved 状态改为 False
                    challenge_copy['solved'] = False
                    # # 为每个副本添加唯一的标识符，避免冲突
                    # challenge_copy['debug_copy_id'] = i
                    # # 同时修改 challenge_code 和 code，确保任务管理器认为它们是不同的题目
                    # original_challenge_code = challenge_copy.get('challenge_code', '')
                    # original_code = challenge_copy.get('code', '')
                    # if original_challenge_code and not original_challenge_code.endswith(f"_{i}"):
                    #     challenge_copy['challenge_code'] = f"{original_challenge_code}_{i}"
                    # if original_code and not original_code.endswith(f"_{i}"):
                    #     challenge_copy['code'] = f"{original_code}_{i}"
                    unsolved_challenges.append(challenge_copy)

            log_system_event(
                "[调试模式] 允许重新攻击已解决的题目，已将 solved 状态改为 unsolved",
                {
                    "total": len(all_challenges),
                    "original_solved": solved_count,
                    "now_unsolved": len(unsolved_challenges),
                    "copies": 1
                }
            )
            return unsolved_challenges
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



# ==================== LLM 调用重试装饰器 ====================
async def retry_llm_call(llm_func, *args, max_retries=5, base_delay=2.0, limiter=None, **kwargs):
    """
    LLM 调用重试装饰器（指数退避策略 + 速率限制）
    
    Args:
        llm_func: LLM 调用函数（如 llm.ainvoke）
        max_retries: 最大重试次数
        base_delay: 基础延迟（秒）
        limiter: RateLimiter 实例（用于控制请求速率）
        
    Returns:
        LLM 响应
        
    Raises:
        Exception: 所有重试都失败后抛出最后一个异常
    """
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            # ⭐ 修复：在调用 LLM 前获取速率限制令牌，避免并发请求过多
            if limiter:
                await limiter.acquire()
            
            result = await llm_func(*args, **kwargs)
            
            # 成功则返回
            if attempt > 0:
                log_system_event(
                    f"[LLM重试] ✅ 第 {attempt + 1} 次尝试成功"
                )
            return result
            
        except Exception as e:
            last_exception = e
            error_msg = str(e)
            
            # 检查是否是速率限制或服务端错误
            is_retryable = any([
                "rate" in error_msg.lower(),
                "limit" in error_msg.lower(),
                "20057" in error_msg,  # MiniMax 特定错误码
                "500" in error_msg,
                "502" in error_msg,
                "503" in error_msg,
                "timeout" in error_msg.lower(),
                "model engine error" in error_msg.lower(),
            ])
            
            if not is_retryable:
                # 非可重试错误，直接抛出
                log_system_event(
                    f"[LLM错误] ❌ 非可重试错误，直接抛出: {error_msg}",
                    level=logging.ERROR
                )
                raise
            
            if attempt < max_retries - 1:
                # 指数退避：2s, 4s, 8s, 16s, 32s
                delay = base_delay * (2 ** attempt)
                log_system_event(
                    f"[LLM重试] ⚠️ 第 {attempt + 1}/{max_retries} 次失败，{delay:.1f}秒后重试",
                    {"error": error_msg}
                )
                await asyncio.sleep(delay)
            else:
                log_system_event(
                    f"[LLM重试] ❌ 已达最大重试次数 ({max_retries})，放弃调用",
                    {"error": error_msg},
                    level=logging.ERROR
                )
    
    # 所有重试都失败，抛出最后一个异常
    raise last_exception

