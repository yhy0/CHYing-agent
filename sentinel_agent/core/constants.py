"""
系统常量定义
============

包含所有魔法数字、配置常量和枚举定义。
"""

# ==================== 节点名称常量 ====================
class NodeNames:
    """节点名称枚举"""
    RECON = "recon"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    TOOLS = "tools"


# ==================== 工具名称常量 ====================
class ToolNames:
    """工具名称枚举"""
    EXECUTE_COMMAND = "execute_command"
    EXECUTE_PYTHON_POC = "execute_python_poc"
    RECORD_VULNERABILITY = "record_vulnerability_discovery"
    RECORD_SUCCESS = "record_successful_exploit"
    RECORD_FAILURE = "record_failed_attempt"
    QUERY_KNOWLEDGE = "query_historical_knowledge"
    GET_CHALLENGES = "get_challenge_list"
    VIEW_HINT = "view_challenge_hint"
    SUBMIT_FLAG = "submit_flag"


# ==================== 系统提示词模板常量 ====================
class PromptTemplates:
    """提示词模板常量"""
    RUN_ID_PREFIX = "sentinel-{node_type}-{timestamp}"
    BENCHMARK_NAME = "Sentinel Security Research"


# ==================== 超时配置 ====================
class Timeouts:
    """超时配置（秒）"""
    COMMAND_EXECUTION = 600  # 命令执行超时（提高到10分钟，适应 nmap 全端口扫描）
    LLM_CALL = 300  # LLM 调用超时
    TOOL_EXECUTION = 60  # 工具执行超时


# ==================== 重试配置 ====================
class RetryConfig:
    """重试配置"""
    MAX_RETRIES = 3  # 最大重试次数
    RETRY_DELAY = 1.0  # 重试延迟（秒）
    BACKOFF_FACTOR = 2.0  # 退避因子


# ==================== 日志和输出配置 ====================
class LogConfig:
    """日志和输出配置"""
    MAX_THINK_PREVIEW_LENGTH = 200  # LLM 思考过程预览长度
    MAX_OUTPUT_PREVIEW_LENGTH = 500  # 命令输出预览长度


# ==================== LangMem 配置 ====================
class MemoryConfig:
    """记忆系统配置"""
    # OpenAI Embedding 配置（可选，用于向量搜索）
    # 如需启用向量搜索，请配置 OPENAI_API_KEY 环境变量
    OPENAI_EMBEDDING_DIMS = 1536  # OpenAI text-embedding-3-small 的维度
    EMBEDDING_MODEL = "openai:text-embedding-3-small"  # 嵌入模型


# ==================== Agent 运行配置 ====================
class AgentConfig:
    """Agent 运行时配置"""
    # 默认值（可通过环境变量覆盖）
    DEFAULT_MAX_ATTEMPTS = 70  # 默认最大尝试次数
    DEFAULT_RECURSION_LIMIT = 80  # 默认递归限制
    DEFAULT_SINGLE_TASK_TIMEOUT = 600  # 默认单题超时（秒）- 10分钟

    @staticmethod
    def get_max_attempts() -> int:
        """获取最大尝试次数（从环境变量或默认值）"""
        import os
        return int(os.getenv("MAX_ATTEMPTS", str(AgentConfig.DEFAULT_MAX_ATTEMPTS)))

    @staticmethod
    def get_recursion_limit() -> int:
        """获取递归限制（从环境变量或默认值）"""
        import os
        return int(os.getenv("RECURSION_LIMIT", str(AgentConfig.DEFAULT_RECURSION_LIMIT)))

    @staticmethod
    def get_single_task_timeout() -> int:
        """获取单题超时时间（从环境变量或默认值）"""
        import os
        return int(os.getenv("SINGLE_TASK_TIMEOUT", str(AgentConfig.DEFAULT_SINGLE_TASK_TIMEOUT)))
