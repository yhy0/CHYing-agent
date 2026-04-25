"""
启动前检查模块
==============

在 Agent 启动前进行环境和配置验证：
- LLM API Key 有效性检查
- Docker 容器状态检查
- MCP 配置检查
- 必要目录检查
"""

import os
import subprocess
import sys
from typing import List, Tuple


PLACEHOLDER_PATTERNS = ["sk-your-", "sk-xxx", "your-", "xxx", "placeholder", "example", "test-key"]


def is_placeholder(value: str) -> bool:
    """检查值是否是占位符"""
    if not value:
        return True
    value_lower = value.lower()
    return any(pattern in value_lower for pattern in PLACEHOLDER_PATTERNS)


def check_api_keys() -> List[Tuple[str, str, bool]]:
    """检查 LLM API 配置"""
    results = []

    api_key = os.getenv("LLM_API_KEY")
    if not api_key:
        results.append(("LLM_API_KEY", "未配置", False))
    elif is_placeholder(api_key):
        results.append(("LLM_API_KEY", f"占位符值 ({api_key[:20]}...)", False))
    else:
        results.append(("LLM_API_KEY", "已配置", True))

    base_url = os.getenv("LLM_BASE_URL")
    if not base_url:
        results.append(("LLM_BASE_URL", "未配置", False))
    else:
        results.append(("LLM_BASE_URL", base_url, True))

    model = os.getenv("LLM_MODEL")
    if not model:
        results.append(("LLM_MODEL", "未配置", False))
    else:
        results.append(("LLM_MODEL", model, True))

    return results


def check_mcp_config() -> Tuple[str, str, bool]:
    """检查 MCP 配置文件（.mcp.json 由 Claude Code CLI 自动加载）"""
    from pathlib import Path
    from chying_agent.utils.path_utils import get_host_agent_work_dir

    mcp_path = Path(get_host_agent_work_dir()) / ".mcp.json"
    if mcp_path.exists():
        return ("MCP 配置", f"CLI 自动加载: {mcp_path}", True)

    return ("MCP 配置", "未找到 .mcp.json（外部 MCP 服务器不可用）", True)


def check_docker_container() -> Tuple[str, str, bool]:
    """检查 Docker 容器状态（容器内模式跳过检查）"""
    from chying_agent.utils.path_utils import is_in_container
    if is_in_container():
        return ("DOCKER_CONTAINER_NAME", "容器内模式，无需 Docker 远程调用", True)

    container_name = os.getenv("DOCKER_CONTAINER_NAME")

    if not container_name:
        return ("DOCKER_CONTAINER_NAME", "未配置（将无法执行命令）", False)

    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        if result.returncode != 0:
            return ("DOCKER_CONTAINER_NAME", "Docker 未运行或无权限", False)

        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
            capture_output=True, text=True, timeout=5
        )

        if result.returncode != 0:
            return ("DOCKER_CONTAINER_NAME", f"容器 '{container_name}' 不存在", False)

        is_running = result.stdout.strip().lower() == "true"
        if not is_running:
            return ("DOCKER_CONTAINER_NAME", f"容器 '{container_name}' 未运行", False)

        return ("DOCKER_CONTAINER_NAME", f"容器 '{container_name}' 运行中", True)

    except FileNotFoundError:
        return ("DOCKER_CONTAINER_NAME", "Docker 未安装", False)
    except subprocess.TimeoutExpired:
        return ("DOCKER_CONTAINER_NAME", "Docker 响应超时", False)
    except Exception as e:
        return ("DOCKER_CONTAINER_NAME", f"检查失败: {e}", False)


def check_langfuse() -> Tuple[str, str, bool]:
    """检查 Langfuse 可观测性配置"""
    from chying_agent.observability import is_langfuse_configured

    if not is_langfuse_configured():
        return ("Langfuse", "未配置（可选，设置 LANGFUSE_PUBLIC_KEY/LANGFUSE_SECRET_KEY 启用）", True)

    try:
        from langfuse import get_client
        client = get_client()
        if client.auth_check():
            base_url = os.getenv("LANGFUSE_BASE_URL", "https://cloud.langfuse.com")
            return ("Langfuse", f"已连接: {base_url}", True)
        else:
            return ("Langfuse", "认证失败，请检查 API Key", False)
    except Exception as e:
        return ("Langfuse", f"连接失败: {e}", False)


def check_kb_status() -> Tuple[str, str, bool]:
    """检查知识库状态（编译后的 wiki 知识库）"""
    from pathlib import Path
    kb_dir = Path(__file__).parent.parent / "knowledge" / "wiki" / "techniques"
    if kb_dir.exists():
        page_count = sum(1 for _ in kb_dir.rglob("*.md"))
        return ("知识库", f"已加载 ({page_count} 个技术页面)", True)
    return ("知识库", "knowledge/wiki/ 目录不存在（可选，不影响运行）", True)


def check_npx() -> Tuple[str, str, bool]:
    """检查 npx 是否可用（chrome-devtools MCP 依赖）"""
    try:
        result = subprocess.run(
            ["npx", "--version"], capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            return ("npx", f"v{version}", True)
        return ("npx", "执行失败", False)
    except FileNotFoundError:
        return (
            "npx",
            "未安装（chrome-devtools MCP 不可用，请安装 Node.js: https://nodejs.org/）",
            False,
        )
    except subprocess.TimeoutExpired:
        return ("npx", "响应超时", False)
    except Exception as e:
        return ("npx", f"检查失败: {e}", False)


def check_directories() -> List[Tuple[str, str, bool]]:
    """检查必要目录"""
    results = []

    for dir_name in ["agent-work/", "logs/"]:
        dir_path = os.path.join(os.getcwd(), dir_name.rstrip("/"))
        if os.path.exists(dir_path):
            results.append((dir_name, "存在", True))
        else:
            results.append((dir_name, "不存在（将自动创建）", True))

    return results


def run_preflight_checks(skip_docker: bool = False) -> bool:
    """运行所有启动前检查"""
    print("\n" + "=" * 60)
    print("🔍 CHYing Agent 启动前检查")
    print("=" * 60)

    all_passed = True
    has_critical_failure = False

    # 1. LLM API 配置
    print("\n📋 LLM API 配置:")
    print("-" * 40)
    api_results = check_api_keys()
    for name, status, passed in api_results:
        icon = "✅" if passed else "❌"
        print(f"  {icon} {name}: {status}")
        if not passed:
            has_critical_failure = True

    # 2. MCP 配置
    print("\n🔌 MCP 配置:")
    print("-" * 40)
    name, status, passed = check_mcp_config()
    icon = "✅" if passed else "⚠️"
    print(f"  {icon} {name}: {status}")

    # 2.1 npx（chrome-devtools MCP 依赖）
    name, status, passed = check_npx()
    icon = "✅" if passed else "⚠️"
    print(f"  {icon} {name}: {status}")
    if not passed:
        all_passed = False

    # 3. Langfuse 可观测性
    print("\n📊 可观测性:")
    print("-" * 40)
    name, status, passed = check_langfuse()
    icon = "✅" if passed else "⚠️"
    print(f"  {icon} {name}: {status}")

    # 4. 知识库
    print("\n📚 知识库:")
    print("-" * 40)
    name, status, passed = check_kb_status()
    icon = "✅" if passed else "⚠️"
    print(f"  {icon} {name}: {status}")

    # 5. Docker
    if not skip_docker:
        print("\n🐳 Docker:")
        print("-" * 40)
        name, status, passed = check_docker_container()
        icon = "✅" if passed else "⚠️"
        print(f"  {icon} {name}: {status}")
        if not passed:
            all_passed = False

    # 6. 目录
    print("\n📁 目录:")
    print("-" * 40)
    for name, status, passed in check_directories():
        icon = "✅" if passed else "⚠️"
        print(f"  {icon} {name}: {status}")

    # 总结
    print("\n" + "=" * 60)
    if has_critical_failure:
        print("❌ 启动前检查失败！请先完成配置：")
        print("")
        print("  1. 复制配置文件: cp .env.example .env")
        print("  2. 编辑 .env，填写：")
        print("     - LLM_API_KEY: API 密钥")
        print("     - LLM_BASE_URL: API 地址")
        print("     - LLM_MODEL: 模型名称")
        print("  3. 启动 Docker: docker start chying-agent-docker")
        print("=" * 60 + "\n")
        return False
    elif not all_passed:
        print("⚠️ 部分检查未通过，功能可能受限")
        print("=" * 60 + "\n")
        return True
    else:
        print("✅ 所有检查通过！")
        print("=" * 60 + "\n")
        return True


if __name__ == "__main__":
    success = run_preflight_checks()
    sys.exit(0 if success else 1)
