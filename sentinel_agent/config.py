import os
from typing import Optional
from dotenv import load_dotenv

class AgentConfig:
    def __init__(self,
                 llm_api_key: str,
                 llm_base_url: str,
                 llm_model_name: str = "deepseek-v3.1-terminus",
                 # 环境模式配置（已移除 test 模式，只支持 competition）
                 env_mode: str = "competition",
                 # Docker 配置（用于 Kali Linux）
                 docker_container_name: Optional[str] = None,
                 # Microsandbox 配置（用于 Python 代码） 云环境还不支持这个
                 sandbox_enabled: bool = False,
                 sandbox_name: str = "sentinel-sandbox"):
        self.llm_api_key = llm_api_key
        self.llm_base_url = llm_base_url
        self.llm_model_name = llm_model_name
        # 环境模式（只支持 competition）
        self.env_mode = env_mode
        # Docker 配置
        self.docker_container_name = docker_container_name
        # Microsandbox 配置
        self.sandbox_enabled = sandbox_enabled
        self.sandbox_name = sandbox_name

def load_agent_config() -> AgentConfig:
    load_dotenv() # 确保.env文件被加载

    # 统一LLM API Key和Base URL的加载
    llm_api_key = os.getenv("DEEPSEEK_API_KEY")
    if not llm_api_key:
        llm_api_key = os.getenv("OPENAI_API_KEY") # 兼容OpenAI
    
    if not llm_api_key:
        raise ValueError("配置错误: 未找到LLM API Key。请设置 DEEPSEEK_API_KEY 或 OPENAI_API_KEY。")

    llm_base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1") # DeepSeek默认Base URL
    llm_model_name = os.getenv("LLM_MODEL_NAME", "deepseek-v3.1-terminus") # 允许覆盖默认模型
    
    # 加载环境模式（只支持 competition）
    env_mode = os.getenv("ENV_MODE", "competition").lower()  # 默认为比赛模式
    if env_mode not in ["competition"]:
        raise ValueError(f"配置错误: ENV_MODE 必须是 'competition'，当前值: {env_mode}")
    
    # 加载 Docker 配置（传统方案）
    docker_container_name = os.getenv("DOCKER_CONTAINER_NAME")
    
    # 加载沙箱配置（Microsandbox）
    sandbox_enabled = os.getenv("SANDBOX_ENABLED", "false").lower() == "true"
    sandbox_name = os.getenv("SANDBOX_NAME", "sentinel-sandbox")

    return AgentConfig(
        llm_api_key=llm_api_key, 
        llm_base_url=llm_base_url, 
        llm_model_name=llm_model_name,
        env_mode=env_mode,
        docker_container_name=docker_container_name,
        sandbox_enabled=sandbox_enabled,
        sandbox_name=sandbox_name
    )