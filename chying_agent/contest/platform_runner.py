"""
CTF 平台集成模块

提供：
- PlatformScraperAgent: 从 CTF 平台爬取题目列表
- SceneManagerAgent: 在平台上启动/管理靶机场景
- FlagSubmitterAgent: 自动提交 flag 到平台
- PlatformRunner: 全流程编排器（scrape -> solve -> submit）
- convert_to_challenge_dicts: 将爬取结果转换为 challenge dict 列表
"""

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..common import log_system_event
from ..claude_sdk.base import BaseClaudeAgent
from ..utils.path_utils import convert_host_path_to_docker, get_host_agent_work_dir

_logger = logging.getLogger(__name__)

# ==================== Schemas ====================

SCRAPER_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "platform_name": {"type": "string", "description": "CTF 平台名称"},
        "challenges": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "category": {"type": "string"},
                    "description": {"type": "string"},
                    "points": {"type": "integer"},
                    "solves": {"type": "integer"},
                    "target_url": {"type": "string"},
                    "attachment_urls": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "attachment_dir": {"type": "string"},
                    "solved": {"type": "boolean"},
                    "challenge_id": {"type": "string"},
                },
                "required": [
                    "name",
                    "category",
                    "description",
                    "points",
                    "solved",
                    "challenge_id",
                ],
            },
        },
    },
    "required": ["platform_name", "challenges"],
}

FLAG_SUBMIT_SCHEMA = {
    "type": "object",
    "properties": {
        "success": {"type": "boolean", "description": "flag 是否提交成功"},
        "message": {"type": "string", "description": "平台返回的提交结果信息"},
    },
    "required": ["success", "message"],
}


# ==================== MCP 配置 ====================

def _load_chrome_devtools_mcp() -> Dict[str, Any]:
    """从 agent-work/.mcp.json 加载 chrome-devtools MCP 配置。"""
    mcp_json_path = get_host_agent_work_dir() / ".mcp.json"
    if not mcp_json_path.exists():
        raise FileNotFoundError(
            f"未找到 MCP 配置文件: {mcp_json_path}\n"
            "请确保 agent-work/.mcp.json 中配置了 chrome-devtools"
        )
    raw = json.loads(mcp_json_path.read_text(encoding="utf-8"))
    servers = raw.get("mcpServers", {})
    chrome_config = servers.get("chrome-devtools")
    if not chrome_config:
        raise ValueError(
            "agent-work/.mcp.json 中未配置 chrome-devtools MCP server"
        )
    return {"chrome-devtools": chrome_config}


def _browser_agent_base_kwargs() -> Dict[str, Any]:
    """浏览器类 Agent 的公共初始化参数。"""
    return {
        "model": os.getenv("LLM_MODEL"),
        "api_key": os.getenv("LLM_API_KEY"),
        "base_url": os.getenv("LLM_BASE_URL"),
        "use_claude_code_preset": True,
        "persistent_session": False,
        "sandbox_enabled": False,
    }


# ==================== Scraper Agent ====================

class PlatformScraperAgent(BaseClaudeAgent):
    """CTF 平台题目爬取 Agent。

    使用 Chrome DevTools MCP 操作已登录的浏览器，
    从 CTF 平台页面提取所有题目信息并下载附件。
    """

    def __init__(self, work_dir: str):
        from ..agents.scraper_agent import SCRAPER_AGENT_SYSTEM_PROMPT

        super().__init__(
            system_prompt=SCRAPER_AGENT_SYSTEM_PROMPT,
            max_turns=100,
            cwd=work_dir,
            **_browser_agent_base_kwargs(),
        )
        self._work_dir = work_dir

    def _get_agent_type(self) -> str:
        return "PlatformScraper"

    def _get_mcp_servers(self) -> Optional[Dict[str, Any]]:
        try:
            return _load_chrome_devtools_mcp()
        except Exception as e:
            _logger.warning(f"Chrome DevTools MCP 加载失败: {e}")
            return None

    def _get_allowed_tools(self) -> List[str]:
        return []

    def _get_disallowed_tools(self) -> List[str]:
        return ["AskUserQuestion"]

    def _get_output_schema(self) -> Optional[Dict[str, Any]]:
        return SCRAPER_OUTPUT_SCHEMA

    async def scrape(
        self, platform_url: str, category: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """爬取 CTF 平台题目列表。

        Args:
            platform_url: 平台 URL
            category: 指定分类名称，只爬该分类；为 None 则爬全部

        Returns:
            结构化 JSON（platform_name + challenges 列表），失败返回 None
        """
        if category:
            category_instruction = (
                f"只爬取 [{category}] 分类下的题目。\n"
                f"点击该分类标签后，翻完该分类的所有页面，不要切换到其他分类。\n"
            )
        else:
            category_instruction = "遍历所有分类，提取每道题目的详细信息\n"

        prompt = (
            f"请打开 CTF 平台页面并爬取题目信息。\n\n"
            f"平台 URL: {platform_url}\n"
            f"附件下载目录: {self._work_dir}\n\n"
            f"分类要求:\n{category_instruction}\n"
            f"其他要求:\n"
            f"1. 先 take_snapshot 查看当前页面，如果不在平台页面则 navigate_page 到上述 URL\n"
            f"2. 下载所有题目附件到 {self._work_dir}/{{Category}}/{{challenge_name}}/ 目录\n"
            f"3. 跳过已解出的题目\n"
            f"4. 如果有分页，翻完所有页面\n"
            f"5. 完成后输出结构化 JSON 结果"
        )
        result = await self.execute_structured(prompt)
        if result.data:
            log_system_event(
                "[PlatformScraper] 爬取完成",
                {"challenge_count": len(result.data.get("challenges", []))},
            )
        return result.data


# ==================== Scene Manager Agent ====================

class SceneManagerAgent(BaseClaudeAgent):
    """CTF 平台场景管理 Agent。

    使用 Chrome DevTools MCP 在平台上为指定题目启动靶机场景，
    等待场景就绪后提取靶机 URL。
    """

    def __init__(self):
        from ..agents.scene_agent import SCENE_MANAGER_SYSTEM_PROMPT, SCENE_MANAGER_OUTPUT_SCHEMA

        super().__init__(
            system_prompt=SCENE_MANAGER_SYSTEM_PROMPT,
            max_turns=30,
            **_browser_agent_base_kwargs(),
        )
        self._scene_schema = SCENE_MANAGER_OUTPUT_SCHEMA

    def _get_agent_type(self) -> str:
        return "SceneManager"

    def _get_mcp_servers(self) -> Optional[Dict[str, Any]]:
        try:
            return _load_chrome_devtools_mcp()
        except Exception as e:
            _logger.warning(f"Chrome DevTools MCP 加载失败: {e}")
            return None

    def _get_allowed_tools(self) -> List[str]:
        return []

    def _get_disallowed_tools(self) -> List[str]:
        return ["AskUserQuestion", "Bash", "Write", "Edit"]

    def _get_output_schema(self) -> Optional[Dict[str, Any]]:
        return self._scene_schema

    async def create_scene(
        self,
        platform_url: str,
        challenge_name: str,
        challenge_id: str,
    ) -> Optional[str]:
        """在平台上启动场景并返回靶机 URL。

        Returns:
            靶机 URL 字符串，失败返回 None
        """
        from ..agents.scene_agent import SCENE_MANAGER_PROMPT

        prompt = SCENE_MANAGER_PROMPT.format(
            platform_url=platform_url,
            challenge_name=challenge_name,
            challenge_id=challenge_id,
        )
        result = await self.execute_structured(prompt)
        if result.data and result.data.get("success"):
            url = result.data.get("target_url", "")
            if url:
                log_system_event(
                    "[SceneManager] 场景启动成功",
                    {"challenge": challenge_name, "target_url": url},
                )
                return url
        msg = result.data.get("message", "") if result.data else "未返回结果"
        log_system_event(
            f"[SceneManager] 场景启动失败: {msg}",
            {"challenge": challenge_name},
            level=logging.WARNING,
        )
        return None


# ==================== Flag Submitter Agent ====================

class FlagSubmitterAgent(BaseClaudeAgent):
    """CTF 平台 Flag 提交 Agent。

    使用 Chrome DevTools MCP 操作已登录的浏览器，
    在 CTF 平台上提交 flag。
    """

    def __init__(self):
        from ..agents.flag_submitter_agent import FLAG_SUBMITTER_AGENT_SYSTEM_PROMPT

        super().__init__(
            system_prompt=FLAG_SUBMITTER_AGENT_SYSTEM_PROMPT,
            max_turns=20,
            **_browser_agent_base_kwargs(),
        )

    def _get_agent_type(self) -> str:
        return "FlagSubmitter"

    def _get_mcp_servers(self) -> Optional[Dict[str, Any]]:
        try:
            return _load_chrome_devtools_mcp()
        except Exception as e:
            _logger.warning(f"Chrome DevTools MCP 加载失败: {e}")
            return None

    def _get_allowed_tools(self) -> List[str]:
        return []

    def _get_disallowed_tools(self) -> List[str]:
        return ["AskUserQuestion", "Bash", "Write", "Edit"]

    def _get_output_schema(self) -> Optional[Dict[str, Any]]:
        return FLAG_SUBMIT_SCHEMA

    async def submit(
        self,
        platform_url: str,
        challenge_name: str,
        challenge_id: str,
        flag: str,
    ) -> Tuple[bool, str]:
        """提交 flag 到平台。

        Returns:
            (success, message) 元组
        """
        prompt = (
            f"请在 CTF 平台上为题目提交 flag。\n\n"
            f"平台 URL: {platform_url}\n"
            f"题目名称: {challenge_name}\n"
            f"题目 ID: {challenge_id}\n"
            f"Flag: {flag}\n\n"
            f"操作步骤:\n"
            f"1. take_snapshot 查看当前页面\n"
            f"2. 导航到平台页面，找到题目 '{challenge_name}'\n"
            f"3. 打开题目详情，找到 flag 提交框\n"
            f"4. 填入 flag 并提交\n"
            f"5. 验证提交结果"
        )
        result = await self.execute_structured(prompt)
        if result.data:
            return result.data.get("success", False), result.data.get("message", "")
        return False, "Flag 提交 agent 未返回结构化结果"


# ==================== Challenge Dict 转换 ====================

def _safe_name(name: str) -> str:
    """将题目名称转换为安全的目录/标识名。"""
    safe = re.sub(r"[^\w\-]", "_", name.strip())
    safe = re.sub(r"_+", "_", safe).strip("_").lower()
    return safe or "unnamed"


def _parse_target_url(url_str: str) -> Tuple[str, int]:
    """从 URL 解析 host 和 port。"""
    parsed = urlparse(url_str if "://" in url_str else f"http://{url_str}")
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def _collect_files_metadata(dir_path: Path) -> Tuple[List[str], List[Dict[str, Any]]]:
    """收集目录下的文件列表和元数据。"""
    files: List[str] = []
    metadata: List[Dict[str, Any]] = []
    if not dir_path.exists():
        return files, metadata
    for f in sorted(dir_path.iterdir()):
        if f.is_file() and not f.name.startswith("."):
            size = f.stat().st_size
            files.append(f.name)
            metadata.append({
                "name": f.name,
                "size": size,
                "size_human": (
                    f"{size / 1024 / 1024:.1f}MB"
                    if size > 1024 * 1024
                    else f"{size / 1024:.1f}KB"
                ),
            })
    return files, metadata


def convert_to_challenge_dicts(
    scraper_result: Dict[str, Any],
    platform_url: str,
    work_dir: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """将 scraper agent 的输出转换为按 category 分组的 challenge dict 列表。

    Returns:
        {category: [challenge_dict, ...]} 分组字典
    """
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    challenges = scraper_result.get("challenges", [])

    for ch in challenges:
        if ch.get("solved"):
            continue

        name = ch.get("name", "unnamed")
        category = ch.get("category", "misc").lower()
        safe = _safe_name(name)
        challenge_code = f"{category}_{safe}"

        challenge_dir = Path(work_dir) / category.capitalize() / safe
        challenge_dir.mkdir(parents=True, exist_ok=True)

        attachment_dir = ch.get("attachment_dir")
        if attachment_dir:
            challenge_dir = Path(attachment_dir)

        target_url = (ch.get("target_url") or "").strip()
        host_work_dir = str(challenge_dir.absolute())
        docker_path = convert_host_path_to_docker(host_work_dir)

        base_dict: Dict[str, Any] = {
            "challenge_code": challenge_code,
            "category": category,
            "difficulty": "unknown",
            "points": ch.get("points", 0),
            "hint_viewed": False,
            "solved": False,
            "_platform_url": platform_url,
            "_challenge_id": ch.get("challenge_id", ""),
            "_challenge_name": name,
            "_challenge_description": ch.get("description", ""),
            "_host_work_dir": host_work_dir,
        }

        if target_url:
            host, port = _parse_target_url(target_url)
            base_dict.update({
                "target_info": {
                    "ip": host,
                    "port": [port],
                    "path": docker_path,
                },
                "_target_url": target_url,
                "_mode": "ctf-web" if category == "web" else "ctf",
            })
        elif category == "web":
            base_dict.update({
                "target_info": {"path": docker_path},
                "_mode": "ctf-web",
                "_needs_scene": True,
            })
        else:
            files, files_metadata = _collect_files_metadata(challenge_dir)
            base_dict.update({
                "target_info": {
                    "path": docker_path,
                    "files": files,
                    "files_metadata": files_metadata,
                },
                "_mode": "ctf",
            })

        grouped.setdefault(category, []).append(base_dict)

    return grouped


# ==================== PlatformRunner ====================

class PlatformRunner:
    """CTF 平台全流程编排器：scrape -> solve -> submit。

    一个自包含的运行器，负责：
    1. 从平台爬取题目列表
    2. 按分类分组，区分有 URL（并发）和需要场景（串行）的题目
    3. 为每道题创建独立 Orchestrator 做题
    4. 做完自动提交 flag 到平台

    浏览器 Tab 模型：
    - 平台操作（scrape/scene/submit）共用一个标签页（串行，不冲突）
    - 每个 solver 的 Task[browser] 子代理自行 new_page 创建新标签页
    """

    def __init__(
        self,
        platform_url: str,
        concurrency: int = 5,
        max_retries: int = 4,
        category_filter: Optional[str] = None,
    ):
        self.platform_url = platform_url
        self.concurrency = concurrency
        self.max_retries = max_retries
        self.category_filter = category_filter

        domain = urlparse(platform_url).hostname or "unknown"
        self._work_dir = os.path.abspath(f"agent-work/ctf/{domain}")
        os.makedirs(self._work_dir, exist_ok=True)

        from ..runtime.singleton import get_config_manager
        self._config = get_config_manager().config

        from ..task_manager import ChallengeStats
        self._stats = ChallengeStats()

        # 统计
        self._total = 0
        self._solved = 0
        self._failed = 0

    async def run(self) -> None:
        """主入口：scrape -> 按分类做题 -> 打印统计。"""
        log_system_event("=" * 60)
        log_system_event(f"[Platform] 开始: {self.platform_url}")
        log_system_event("=" * 60)

        # 1. 爬取题目
        scraper_result = await self._scrape_challenges()
        if not scraper_result:
            log_system_event("[Platform] 爬取失败或无题目", level=logging.ERROR)
            return

        # 2. 转换并分组
        grouped = convert_to_challenge_dicts(
            scraper_result, self.platform_url, self._work_dir,
        )
        if not grouped:
            log_system_event("[Platform] 无未解出的题目")
            return

        # 3. 按分类做题
        for category, challenges in grouped.items():
            if self.category_filter and category != self.category_filter.lower():
                continue
            await self._run_category(category, challenges)

        # 4. 打印最终统计
        self._print_summary()

    async def _scrape_challenges(self) -> Optional[Dict[str, Any]]:
        """爬取所有题目（一次性，按 category_filter 过滤）。"""
        log_system_event("[Platform] 启动 Scraper Agent 爬取题目")
        scraper = PlatformScraperAgent(work_dir=self._work_dir)
        return await scraper.scrape(
            self.platform_url, category=self.category_filter,
        )

    async def _run_category(self, category: str, challenges: List[Dict]) -> None:
        """处理一个分类：先并发做不需要场景的，再串行做需要场景的。"""
        needs_scene = [c for c in challenges if c.get("_needs_scene")]
        can_solve = [c for c in challenges if not c.get("_needs_scene")]
        self._total += len(can_solve) + len(needs_scene)

        log_system_event(
            f"[Platform] === 分类 {category.upper()} ===",
            {
                "可直接做": len(can_solve),
                "需场景": len(needs_scene),
            },
        )

        if can_solve:
            log_system_event(
                f"[Platform] 并发做题 (concurrency={self.concurrency}): "
                f"{len(can_solve)} 道"
            )
            await self._solve_concurrent(can_solve)

        for idx, ch in enumerate(needs_scene, 1):
            log_system_event(
                f"[Platform] 串行做题 [{idx}/{len(needs_scene)}]: "
                f"{ch['challenge_code']} (需启动场景)"
            )
            await self._solve_with_scene(ch)

    async def _solve_concurrent(self, challenges: List[Dict]) -> None:
        """并发做题，用信号量控制并发数。"""
        semaphore = asyncio.Semaphore(self.concurrency)

        async def worker(ch: Dict) -> None:
            async with semaphore:
                await self._solve_and_submit(ch)

        results = await asyncio.gather(
            *(worker(ch) for ch in challenges),
            return_exceptions=True,
        )
        for i, r in enumerate(results):
            if isinstance(r, BaseException):
                code = challenges[i].get("challenge_code", "?")
                log_system_event(
                    f"[Platform] 并发做题异常: {code}: {r}",
                    level=logging.ERROR,
                )
                self._failed += 1

    async def _solve_with_scene(self, challenge: Dict) -> None:
        """串行：创建场景 -> 做题 -> 提交。"""
        target_url = await self._create_scene(challenge)
        if target_url:
            challenge["_target_url"] = target_url
            host, port = _parse_target_url(target_url)
            challenge["target_info"]["ip"] = host
            challenge["target_info"]["port"] = [port]
        else:
            log_system_event(
                f"[Platform] 跳过 {challenge['challenge_code']}: 场景启动失败",
                level=logging.WARNING,
            )
            self._failed += 1
            return

        await self._solve_and_submit(challenge)

    async def _solve_and_submit(self, challenge: Dict) -> None:
        """原子单元：做一道题 + 自动提交 flag。

        每道题创建独立的 Orchestrator，做完即销毁，题目间完全隔离。
        """
        from ..challenge_solver import solve_single_challenge
        from ..runtime.context import set_submit_flag_callback, clear_submit_flag_callback

        challenge_code = challenge["challenge_code"]

        # 去重集合：同一题内跨 attempt 不重复提交
        _submitted: set[str] = set()

        async def _submit_flag_callback(flag: str) -> Tuple[bool, str]:
            """将 agent 的 submit_flag MCP 调用桥接到 FlagSubmitterAgent。"""
            if flag in _submitted:
                return True, "Flag 已提交过（跳过重复提交）"
            success, message = await self._submit_flag(challenge, flag)
            if success:
                _submitted.add(flag)
            return success, message

        attempt = 0
        result = None

        set_submit_flag_callback(_submit_flag_callback)
        try:
            while attempt <= self.max_retries:
                if attempt > 0:
                    log_system_event(
                        f"[Platform] 重试 {challenge_code} "
                        f"({attempt}/{self.max_retries})"
                    )

                try:
                    result = await solve_single_challenge(
                        challenge=challenge,
                        config=self._config,
                        stats=self._stats,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    log_system_event(
                        f"[Platform] {challenge_code} 异常: {e}",
                        level=logging.ERROR,
                    )

                if result and result.get("success"):
                    self._solved += 1
                    flag = result.get("flag", "")
                    log_system_event(f"[Platform] {challenge_code} 解题成功: {flag}")

                    # 若 agent 已通过 MCP 工具提交过，此处去重跳过
                    if flag and flag not in _submitted:
                        await self._submit_flag(challenge, flag)
                    return

                attempt += 1
        finally:
            clear_submit_flag_callback()

        self._failed += 1
        log_system_event(
            f"[Platform] {challenge_code} 最终失败 (尝试 {attempt} 次)"
        )

    async def _create_scene(self, challenge: Dict) -> Optional[str]:
        """用浏览器在平台上为题目启动场景，返回靶机 URL。"""
        agent = SceneManagerAgent()
        try:
            return await agent.create_scene(
                platform_url=self.platform_url,
                challenge_name=challenge.get("_challenge_name", ""),
                challenge_id=challenge.get("_challenge_id", ""),
            )
        except Exception as e:
            log_system_event(
                f"[SceneManager] 异常: {e}",
                level=logging.WARNING,
            )
            return None

    async def _submit_flag(self, challenge: Dict, flag: str) -> Tuple[bool, str]:
        """用浏览器在平台上提交 flag，返回 (success, message)。"""
        agent = FlagSubmitterAgent()
        try:
            success, message = await agent.submit(
                platform_url=self.platform_url,
                challenge_name=challenge.get("_challenge_name", ""),
                challenge_id=challenge.get("_challenge_id", ""),
                flag=flag,
            )
            status = "成功" if success else "失败"
            log_system_event(
                f"[FlagSubmitter] {challenge['challenge_code']} 提交{status}: {message}"
            )
            return success, message
        except Exception as e:
            log_system_event(
                f"[FlagSubmitter] {challenge['challenge_code']} 提交异常: {e}",
                level=logging.WARNING,
            )
            return False, str(e)

    def _print_summary(self) -> None:
        """打印最终统计。"""
        log_system_event("=" * 60)
        log_system_event("[Platform] 最终统计")
        log_system_event("-" * 40)
        log_system_event(
            f"  总计: {self._total}  "
            f"成功: {self._solved}  "
            f"失败: {self._failed}"
        )
        if self._total > 0:
            rate = self._solved / self._total * 100
            log_system_event(f"  成功率: {rate:.1f}%")
        log_system_event("=" * 60)
