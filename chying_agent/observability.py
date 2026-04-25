"""
Langfuse 可观测性集成
====================

通过 langsmith 的 Claude Agent SDK 集成库，将所有 Claude SDK 调用
自动追踪到 Langfuse（基于 OpenTelemetry）。

初始化条件：环境变量 LANGFUSE_PUBLIC_KEY 和 LANGFUSE_SECRET_KEY 已配置。
未配置时静默跳过，不影响正常运行。
"""

import os
import logging

logger = logging.getLogger(__name__)

_initialized = False


def is_langfuse_configured() -> bool:
    """检查 Langfuse 环境变量是否已配置"""
    return bool(
        os.getenv("LANGFUSE_PUBLIC_KEY")
        and os.getenv("LANGFUSE_SECRET_KEY")
    )


def init_observability() -> bool:
    """初始化 Langfuse + OpenTelemetry 追踪

    Returns:
        True 如果初始化成功，False 如果跳过或失败
    """
    global _initialized
    if _initialized:
        return True

    if not is_langfuse_configured():
        logger.debug("Langfuse 未配置（缺少 LANGFUSE_PUBLIC_KEY/LANGFUSE_SECRET_KEY），跳过可观测性初始化")
        return False

    # langsmith 的 claude-agent-sdk 集成需要这些环境变量
    os.environ.setdefault("LANGSMITH_OTEL_ENABLED", "true")
    os.environ.setdefault("LANGSMITH_OTEL_ONLY", "true")
    os.environ.setdefault("LANGSMITH_TRACING", "true")

    try:
        from langsmith.integrations.claude_agent_sdk import configure_claude_agent_sdk
        configure_claude_agent_sdk()

        # 验证 Langfuse 客户端连通性
        from langfuse import get_client
        client = get_client()
        if client.auth_check():
            _initialized = True
            logger.info("Langfuse 可观测性已启用")
            return True
        else:
            logger.warning("Langfuse 认证失败，请检查 LANGFUSE_PUBLIC_KEY/LANGFUSE_SECRET_KEY")
            return False

    except ImportError as e:
        logger.warning(f"Langfuse 依赖缺失: {e}（运行 uv sync 安装依赖）")
        return False
    except Exception as e:
        logger.warning(f"Langfuse 初始化失败: {e}")
        return False


def shutdown_observability():
    """在程序退出前刷新 Langfuse 缓冲区"""
    if not _initialized:
        return

    try:
        from langfuse import get_client
        client = get_client()
        client.flush()
        client.shutdown()
    except Exception:
        pass
