import os
import json
from langchain_deepseek import ChatDeepSeek
from langchain_core.language_models import BaseChatModel
from sentinel_agent.common import log_system_event
from sentinel_agent.config import AgentConfig


def create_model(
    config: AgentConfig,
    temperature: float = 0.5,
    max_tokens: int = 12800,
    timeout: int = 600,
    max_retries: int = 20  # ⭐ 提升重试次数：2 → 10（应对并发速率限制）
) -> BaseChatModel:
    """
    创建模型实例

    Args:
        config: AgentConfig实例，包含LLM配置。
        temperature: 温度参数。
        max_tokens: 最大token数。
        timeout: 超时时间。
        max_retries: 重试次数。

    Returns:
        BaseChatModel: 模型实例。
    """
    model_name = config.llm_model_name
    model = ChatDeepSeek(
        api_base=config.llm_base_url,
        api_key=config.llm_api_key,
        model=model_name,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        max_retries=max_retries,
        streaming=False,  # 禁用流式输出以支持结构化输出
        extra_body={
            "thinking": {
                "type": "enabled",
                "enable_search": True,
            }
        }
    )

    log_system_event(
        "✅ 创建Sentinel Agent模型实例",
        {
            "model": model_name,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": timeout,
            "max_retries": max_retries,
        },
    )

    return model
