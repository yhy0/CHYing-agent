"""
统一配置管理
============

集中管理所有 Agent 相关的配置，包括：
- LLM API 配置
- Docker 执行器配置
- MCP 配置
- 运行时参数

环境变量命名规范：
- LLM_* : LLM API 配置
- DOCKER_* : Docker 配置
- MCP_* : MCP 配置
"""

import os
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class RunMode(str, Enum):
    """运行模式枚举"""
    CTF = "ctf"
    CTF_WEB = "ctf-web"
    PENTEST = "pentest"


AVAILABLE_MODES = [mode.value for mode in RunMode]


@dataclass
class LLMConfig:
    """LLM API 配置"""

    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    response_language: str = ""
    cli_path: Optional[str] = None
    cli_model_routing: bool = True

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """从环境变量加载配置"""
        return cls(
            model=os.getenv("LLM_MODEL") or None,
            api_key=os.getenv("LLM_API_KEY") or None,
            base_url=os.getenv("LLM_BASE_URL") or None,
            response_language=os.getenv("RESPONSE_LANGUAGE", "").strip().lower(),
            cli_path=os.getenv("CLAUDE_CLI_PATH") or None,
            cli_model_routing=os.getenv("CLI_MODEL_ROUTING", "true").lower() in ("true", "1", "yes"),
        )

    @property
    def use_local_cli(self) -> bool:
        """是否使用本地 CLI 的模型路由（需同时满足：有 cli_path 且 cli_model_routing 开启）"""
        return bool(self.cli_path) and self.cli_model_routing

    @property
    def is_configured(self) -> bool:
        """检查是否配置了 API 或本地 CLI"""
        return bool(self.api_key) or self.use_local_cli



@dataclass
class DockerConfig:
    """Docker 执行器配置"""

    container_name: Optional[str] = None
    passthrough_env: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "DockerConfig":
        """从环境变量加载配置"""
        container_name = os.getenv("DOCKER_CONTAINER_NAME")
        # 解析白名单：DOCKER_PASSTHROUGH_ENV=GH_TOKEN,SHODAN_API_KEY
        raw = os.getenv("DOCKER_PASSTHROUGH_ENV", "")
        passthrough: dict[str, str] = {}
        for key in raw.split(","):
            key = key.strip()
            if key and key in os.environ:
                passthrough[key] = os.environ[key]
        return cls(container_name=container_name, passthrough_env=passthrough)

    @property
    def is_configured(self) -> bool:
        return bool(self.container_name)


@dataclass
class MCPConfig:
    """MCP 服务器配置"""

    config_path: str = ""

    @classmethod
    def from_env(cls) -> "MCPConfig":
        return cls(config_path=os.getenv("MCP_CONFIG_PATH", ""))

    @property
    def is_configured(self) -> bool:
        from pathlib import Path

        if self.config_path:
            return Path(self.config_path).exists()
        default_path = Path(__file__).parent.parent / ".mcp.json"
        return default_path.exists()


@dataclass
class RAGConfig:
    """知识库配置

    已从 RAG（embedding + BM25 检索）迁移到 Compiled Knowledge Base
    （预编译的 markdown wiki，frontmatter 关键词匹配）。

    保留 enabled 开关用于全局控制知识库功能。
    """

    enabled: bool = True

    @classmethod
    def from_env(cls) -> "RAGConfig":
        return cls(
            enabled=os.getenv("RAG_ENABLED", "true").lower() in ("true", "1", "yes"),
        )


@dataclass
class RuntimeConfig:
    """运行时配置"""

    single_task_timeout: int = 2400
    db_echo: bool = False

    @classmethod
    def from_env(cls) -> "RuntimeConfig":
        return cls(
            single_task_timeout=int(os.getenv("SINGLE_TASK_TIMEOUT", "2400")),
            db_echo=os.getenv("DB_ECHO", "false").lower() == "true",
        )


@dataclass
class AgentConfig:
    """统一配置类"""

    brain: LLMConfig
    docker: DockerConfig
    mcp: MCPConfig
    runtime: RuntimeConfig
    rag: RAGConfig

    @classmethod
    def from_env(cls) -> "AgentConfig":
        return cls(
            brain=LLMConfig.from_env(),
            docker=DockerConfig.from_env(),
            mcp=MCPConfig.from_env(),
            runtime=RuntimeConfig.from_env(),
            rag=RAGConfig.from_env(),
        )

    @property
    def docker_container_name(self) -> Optional[str]:
        return self.docker.container_name


def load_agent_config() -> AgentConfig:
    """从环境变量加载 Agent 配置"""
    return AgentConfig.from_env()


__all__ = [
    "RunMode",
    "AVAILABLE_MODES",
    "LLMConfig",
    "DockerConfig",
    "MCPConfig",
    "RAGConfig",
    "RuntimeConfig",
    "AgentConfig",
    "load_agent_config",
]
