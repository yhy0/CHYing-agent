"""
多目标并发管理器
================

支持 CTF 比赛开始时同时处理多种类型题目（Web/PWN/Misc/Crypto），抢夺一血。

使用方式：
    # 手动指定
    python main.py --web urls.txt --pwn PWN/ --misc Misc/ --crypto Crypto/ -c 5

    # 自动检测（从 agent-work/ctf/ 目录）
    python main.py -m ctf

自动检测目录结构：
    agent-work/
    └── ctf/
        ├── web-targets.txt    # Web 题目 URL 列表
        ├── PWN/               # PWN 题目目录
        ├── Misc/              # Misc 题目目录
        └── Crypto/            # Crypto 题目目录
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

# 从 path_utils 导入路径转换函数
from chying_agent.utils.path_utils import convert_host_path_to_docker


def _get_file_magic_type(filepath: str) -> str:
    """
    使用 python-magic 获取文件类型（类似 file 命令）

    Args:
        filepath: 文件路径

    Returns:
        文件类型描述字符串
    """
    try:
        import magic
        file_type = magic.from_file(filepath)
        return file_type
    except ImportError:
        return "unknown (python-magic not installed)"
    except Exception as e:
        return f"unknown ({str(e)})"


# 使用统一的路径转换函数
_to_docker_path = convert_host_path_to_docker


from chying_agent.common import log_system_event
from chying_agent.task_manager import ChallengeStats


@dataclass
class CategoryConfig:
    """单个类型的配置"""

    name: str
    challenges: List[Dict]
    stats: ChallengeStats = field(default=None)

    # 统计
    completed: int = 0
    success: int = 0
    failed: int = 0


def _sanitize_dirname(name: str) -> str:
    """
    将字符串转换为安全的目录名

    - 替换不安全字符（/、\、:、*、?、"、<、>、| 等）
    - 保留中文和其他 Unicode 字符
    - 限制长度（避免路径过长）

    Args:
        name: 原始名称

    Returns:
        安全的目录名
    """
    import re
    # 替换不安全字符为下划线
    safe_name = re.sub(r'[/\\:*?"<>|]', '_', name)
    # 合并连续的下划线
    safe_name = re.sub(r'_+', '_', safe_name)
    # 去除首尾下划线
    safe_name = safe_name.strip('_')
    return safe_name or "unknown"


def parse_web_challenges(urls_file: str) -> List[Dict]:
    """
    从文件解析 Web URL 列表，并自动创建题目工作目录

    文件格式：每行一个 URL

    目录结构：
        agent-work/ctf/Web/
        ├── target_host_port_1/    # 自动创建
        │   └── notes.md           # 可选，用于记录
        ├── target_host_port_2/
        │   └── ...

    Args:
        urls_file: URL 文件路径

    Returns:
        challenge 列表
    """
    from urllib.parse import urlparse

    challenges = []
    file_path = Path(urls_file)

    if not file_path.exists():
        raise FileNotFoundError(f"URL 文件不存在: {urls_file}")

    # 确定 Web 题目工作目录（与 urls_file 同级的 Web/ 目录）
    # 例如: agent-work/ctf/web-targets.txt -> agent-work/ctf/Web/
    ctf_dir = file_path.parent
    web_work_dir = ctf_dir / "Web"
    web_work_dir.mkdir(parents=True, exist_ok=True)

    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            url = line.strip()
            if not url or url.startswith("#"):
                continue

            # 如果没有协议前缀，添加 http://
            if not url.startswith(("http://", "https://")):
                url = f"http://{url}"

            try:
                parsed = urlparse(url)
                host = parsed.hostname or "127.0.0.1"
                port = parsed.port or (443 if parsed.scheme == "https" else 80)

                # 生成安全的目录名（包含路径信息，区分同域名不同路径）
                path_part = parsed.path.strip("/")
                if path_part:
                    dir_name = _sanitize_dirname(f"{host}_{port}_{path_part.replace('/', '_')}")
                else:
                    dir_name = _sanitize_dirname(f"{host}_{port}")
                challenge_dir = web_work_dir / dir_name

                # 检查目录是否已存在
                is_resume = challenge_dir.exists()
                if is_resume:
                    # 目录已存在，检查是否已完成（有 flag 文件或标记）
                    flag_file = challenge_dir / "flag.txt"
                    solved_marker = challenge_dir / ".solved"
                    if flag_file.exists() or solved_marker.exists():
                        log_system_event(
                            f"[解析] ✅ 跳过已完成的 Web 题目",
                            {"目录": dir_name, "URL": url},
                            level=logging.DEBUG,
                        )
                        continue
                    # 未完成，恢复继续
                    log_system_event(
                        f"[解析] 🔄 恢复未完成的 Web 题目",
                        {"目录": dir_name, "URL": url},
                    )
                else:
                    # 创建题目工作目录
                    challenge_dir.mkdir(parents=True, exist_ok=True)


                challenge = {
                    "challenge_code": f"web_{dir_name}",
                    "difficulty": "unknown",
                    "points": 0,
                    "hint_viewed": False,
                    "solved": False,
                    "target_info": {
                        "ip": host,
                        "port": [port],
                        # 添加工作目录路径（Docker 容器内路径）
                        "path": _to_docker_path(str(challenge_dir.absolute())),
                    },
                    "_target_url": url,
                    "_mode": "ctf-web",
                    "category": "web",
                    # 保存宿主机工作目录路径（用于日志等）
                    "_host_work_dir": str(challenge_dir.absolute()),
                }
                challenges.append(challenge)

                log_system_event(
                    f"[解析] ✅ 创建 Web 题目工作目录",
                    {"目录": str(challenge_dir), "URL": url},
                )

            except Exception as e:
                log_system_event(
                    f"[解析] ⚠️ 跳过无效 URL (行 {line_num}): {url} - {str(e)}",
                    level=logging.WARNING,
                )

    log_system_event(
        f"[解析] ✅ Web 题目解析完成",
        {"文件": urls_file, "题目数": len(challenges), "工作目录": str(web_work_dir)},
    )

    return challenges


def parse_directory_challenges(directory: str, category: str) -> List[Dict]:
    """
    从目录解析题目（PWN/Misc/Crypto）

    目录结构：
        PWN/
        ├── challenge1/
        │   ├── pwn (binary)
        │   └── libc.so.6
        ├── challenge2/
        │   └── ...

    Args:
        directory: 题目目录路径
        category: 题目类型 (pwn, misc, crypto)

    Returns:
        challenge 列表
    """
    challenges = []
    dir_path = Path(directory)

    if not dir_path.exists():
        raise FileNotFoundError(f"目录不存在: {directory}")

    if not dir_path.is_dir():
        raise ValueError(f"路径不是目录: {directory}")

    # 遍历子目录，每个子目录是一道题
    for challenge_dir in sorted(dir_path.iterdir()):
        if not challenge_dir.is_dir():
            continue

        # 跳过隐藏目录
        if challenge_dir.name.startswith("."):
            continue

        # 获取目录中的文件列表（包含元数据）
        files = []
        files_metadata = []
        for f in challenge_dir.iterdir():
            if f.is_file() and not f.name.startswith("."):
                files.append(f.name)
                # 获取文件元数据
                try:
                    stat = f.stat()
                    size = stat.st_size
                    # 人类可读的大小
                    if size >= 1024 * 1024:
                        size_human = f"{size / (1024 * 1024):.2f} MB"
                    elif size >= 1024:
                        size_human = f"{size / 1024:.2f} KB"
                    else:
                        size_human = f"{size} B"

                    # 获取文件类型（使用 python-magic）
                    file_type = _get_file_magic_type(str(f))

                    files_metadata.append({
                        "name": f.name,
                        "size": size,
                        "size_human": size_human,
                        "file_type": file_type,
                    })
                except Exception:
                    files_metadata.append({
                        "name": f.name,
                        "size": 0,
                        "size_human": "unknown",
                        "file_type": "unknown",
                    })

        if not files:
            log_system_event(
                f"[解析] ⚠️ 跳过空目录: {challenge_dir.name}", level=logging.WARNING
            )
            continue

        challenge = {
            "challenge_code": f"{category}_{challenge_dir.name}",
            "difficulty": "unknown",
            "points": 0,
            "hint_viewed": False,
            "solved": False,
            "target_info": {
                "path": _to_docker_path(str(challenge_dir.absolute())),
                "files": files,
                "files_metadata": files_metadata,  # 包含文件元数据
            },
            "_mode": "ctf",
            "category": category,
        }
        challenges.append(challenge)

    log_system_event(
        f"[解析] ✅ {category.upper()} 题目解析完成",
        {"目录": directory, "题目数": len(challenges)},
    )

    return challenges


# ==================== 自动检测 CTF 题目 ====================

# 默认 CTF 目录（相对于项目根目录）
DEFAULT_CTF_DIR = "agent-work/ctf"

# Web 题目文件名（支持多种命名）
WEB_TARGET_FILES = ["web-targets.txt", "web.txt", "urls.txt", "targets.txt"]

# 目录类型映射（目录名 -> 类型，不区分大小写）
CATEGORY_DIR_NAMES = {
    "pwn": "pwn",
    "misc": "misc",
    "crypto": "crypto",
    "reverse": "reverse",
    "forensics": "forensics",
    "re": "reverse",  # 别名
}


def auto_detect_ctf_challenges(
    ctf_dir: Optional[str] = None, project_root: Optional[Path] = None
) -> Dict[str, Any]:
    """
    自动检测 CTF 题目

    从 agent-work/ctf/ 目录自动检测各类型题目：
    - web-targets.txt / web.txt / urls.txt -> Web 题目
    - PWN/ -> PWN 题目
    - Misc/ -> Misc 题目
    - Crypto/ -> Crypto 题目

    Args:
        ctf_dir: CTF 目录路径（可选，默认 agent-work/ctf）
        project_root: 项目根目录（可选，默认自动检测）

    Returns:
        检测结果字典：
        {
            "found": bool,           # 是否找到任何题目
            "ctf_dir": str,          # CTF 目录路径
            "web_file": str | None,  # Web 题目文件路径
            "pwn_dir": str | None,   # PWN 目录路径
            "misc_dir": str | None,  # Misc 目录路径
            "crypto_dir": str | None,# Crypto 目录路径
            "categories": dict,      # 各类型题目数量
        }
    """
    # 确定项目根目录
    if project_root is None:
        project_root = Path(__file__).parent.parent

    # 确定 CTF 目录
    if ctf_dir:
        ctf_path = Path(ctf_dir)
    else:
        ctf_path = project_root / DEFAULT_CTF_DIR

    result = {
        "found": False,
        "ctf_dir": str(ctf_path),
        "web_file": None,
        "pwn_dir": None,
        "misc_dir": None,
        "crypto_dir": None,
        "reverse_dir": None,
        "forensics_dir": None,
        "categories": {},
    }

    if not ctf_path.exists():
        log_system_event(f"[自动检测] CTF 目录不存在: {ctf_path}", level=logging.DEBUG)
        return result

    if not ctf_path.is_dir():
        log_system_event(f"[自动检测] 路径不是目录: {ctf_path}", level=logging.WARNING)
        return result

    log_system_event(f"[自动检测] 扫描 CTF 目录: {ctf_path}")

    # 1. 检测 Web 题目文件
    for web_file in WEB_TARGET_FILES:
        web_path = ctf_path / web_file
        if web_path.exists() and web_path.is_file():
            # 检查文件是否有内容
            try:
                with open(web_path, "r", encoding="utf-8") as f:
                    lines = [
                        l.strip() for l in f if l.strip() and not l.startswith("#")
                    ]
                if lines:
                    result["web_file"] = str(web_path)
                    result["categories"]["web"] = len(lines)
                    log_system_event(
                        f"[自动检测] ✅ 发现 Web 题目",
                        {"文件": web_file, "数量": len(lines)},
                    )
                    break
            except Exception as e:
                log_system_event(
                    f"[自动检测] ⚠️ 读取 Web 文件失败: {web_file} - {e}",
                    level=logging.WARNING,
                )

    # 2. 检测各类型目录
    for item in ctf_path.iterdir():
        if not item.is_dir():
            continue

        # 跳过隐藏目录
        if item.name.startswith("."):
            continue

        # 匹配目录类型（不区分大小写）
        dir_name_lower = item.name.lower()
        category = CATEGORY_DIR_NAMES.get(dir_name_lower)

        if category:
            # 统计子目录数量（每个子目录是一道题）
            challenge_count = sum(
                1 for d in item.iterdir() if d.is_dir() and not d.name.startswith(".")
            )

            if challenge_count > 0:
                result[f"{category}_dir"] = str(item)
                result["categories"][category] = challenge_count
                log_system_event(
                    f"[自动检测] ✅ 发现 {category.upper()} 题目",
                    {"目录": item.name, "数量": challenge_count},
                )

    # 判断是否找到任何题目
    result["found"] = bool(result["categories"])

    if result["found"]:
        total = sum(result["categories"].values())
        log_system_event(
            f"[自动检测] 📋 检测完成",
            {"总题目数": total, "类型": list(result["categories"].keys())},
        )
    else:
        log_system_event(
            f"[自动检测] ⚠️ 未发现任何题目",
            {"目录": str(ctf_path)},
            level=logging.WARNING,
        )

    return result


def create_ctf_directory_structure(ctf_dir: Optional[str] = None) -> str:
    """
    创建 CTF 目录结构模板

    Args:
        ctf_dir: CTF 目录路径（可选，默认 agent-work/ctf）

    Returns:
        创建的目录路径
    """
    project_root = Path(__file__).parent.parent

    if ctf_dir:
        ctf_path = Path(ctf_dir)
    else:
        ctf_path = project_root / DEFAULT_CTF_DIR

    # 创建目录结构
    ctf_path.mkdir(parents=True, exist_ok=True)
    (ctf_path / "Web").mkdir(exist_ok=True)      # Web 题目工作目录
    (ctf_path / "PWN").mkdir(exist_ok=True)
    (ctf_path / "Misc").mkdir(exist_ok=True)
    (ctf_path / "Crypto").mkdir(exist_ok=True)

    # 创建 Web 题目模板文件
    web_file = ctf_path / "web-targets.txt"
    if not web_file.exists():
        web_file.write_text(
            "# Web 题目 URL 列表\n"
            "# 每行一个 URL，支持 http:// 和 https://\n"
            "# 示例：\n"
            "# http://192.168.1.100:8080\n"
            "# https://web01.ctf.com\n"
            "#\n"
            "# 注意：解析时会自动在 Web/ 目录下创建对应的题目文件夹\n"
        )

    log_system_event(f"[CTF] ✅ 目录结构已创建", {"路径": str(ctf_path)})

    return str(ctf_path)


class MultiTargetManager:
    """
    多目标并发管理器

    支持同时运行多种类型的题目，每种类型有独立的并发池。
    """

    def __init__(
        self,
        config,
        max_retries: int = 4,
        concurrency: int = 5,
    ):
        """
        初始化管理器

        Args:
            config: 配置对象
            max_retries: 最大重试次数
            concurrency: 全局最大并发数
        """
        self.config = config
        self.max_retries = max_retries
        self.concurrency = concurrency

        self.categories: Dict[str, CategoryConfig] = {}
        self._running = False
        self._tasks: List[asyncio.Task] = []

        # 动态扫描器（延迟加载）
        self._dynamic_scanner = None
        self._dynamic_scan_enabled = False

    def add_category(self, name: str, challenges: List[Dict]):
        """
        添加一个题目类型

        Args:
            name: 类型名称 (web, pwn, misc, crypto)
            challenges: 题目列表
        """
        if not challenges:
            log_system_event(
                f"[多目标] ⚠️ {name.upper()} 类型无题目，跳过", level=logging.WARNING
            )
            return

        self.categories[name] = CategoryConfig(
            name=name,
            challenges=challenges,
            stats=ChallengeStats(),
        )

        log_system_event(
            f"[多目标] ✅ 添加 {name.upper()} 类型",
            {"题目数": len(challenges)},
        )

    def enable_dynamic_scan(
        self,
        scan_interval: int = 60,
        ctf_dir: Optional[str] = None,
    ):
        """
        启用动态题目扫描模式

        启用后，系统会定期扫描 CTF 目录，自动发现并添加新增题目。

        Args:
            scan_interval: 扫描间隔（秒），默认 60 秒
            ctf_dir: CTF 目录路径（默认 agent-work/ctf）
        """
        self._dynamic_scan_enabled = True
        self._dynamic_scan_interval = scan_interval
        self._dynamic_ctf_dir = ctf_dir

        log_system_event(
            f"[多目标] 🔍 动态扫描已启用",
            {"扫描间隔": f"{scan_interval}秒", "目录": ctf_dir or "agent-work/ctf"},
        )

    async def run(self, dynamic_scan: bool = False):
        """
        运行所有类型的题目

        根据配置分为两种模式：
        1. 普通模式：处理初始加载的题目，完成后退出
        2. 动态扫描模式：持续扫描目录，实时处理新增题目

        每种类型独立并发，互不影响。

        Args:
            dynamic_scan: 是否启用动态扫描模式
        """
        # 如果通过参数传入动态扫描标志，确保已启用
        if dynamic_scan and not self._dynamic_scan_enabled:
            self._dynamic_scan_enabled = True

        if not self.categories:
            log_system_event("[多目标] ❌ 没有任何题目可运行", level=logging.ERROR)
            return

        self._running = True

        # 打印启动信息
        total_challenges = sum(len(cat.challenges) for cat in self.categories.values())
        log_system_event(
            "=" * 80 + "\n" + "🚀 CHYing Agent 多目标并发模式启动\n" + "=" * 80
        )

        scan_mode = "🔍 动态扫描模式" if self._dynamic_scan_enabled else "普通模式"
        log_system_event(
            "[多目标] 任务概览",
            {
                "运行模式": scan_mode,
                "总题目数": total_challenges,
                "全局并发数": self.concurrency,
                "类型数": len(self.categories),
                **{
                    f"{name.upper()} 题目": len(cat.challenges)
                    for name, cat in self.categories.items()
                },
            },
        )

        try:
            # 启动动态扫描器（如果启用）
            if self._dynamic_scan_enabled:
                await self._start_dynamic_scanner()

            # 为每种类型创建一个协程
            category_tasks = [
                asyncio.create_task(
                    self._run_category(cat_config), name=f"category_{cat_config.name}"
                )
                for cat_config in self.categories.values()
            ]
            self._tasks = category_tasks

            # 等待所有类型完成
            await asyncio.gather(*category_tasks, return_exceptions=True)

        except KeyboardInterrupt:
            log_system_event(
                "\n🛑 收到中断信号，正在优雅退出...", level=logging.WARNING
            )
            self._running = False

            # 取消所有任务
            for task in self._tasks:
                task.cancel()

            # 等待任务取消完成
            await asyncio.gather(*self._tasks, return_exceptions=True)

        finally:
            # 停止动态扫描器
            if self._dynamic_scanner:
                await self._dynamic_scanner.stop()

            # 打印最终统计
            await self._print_final_status()

    async def _start_dynamic_scanner(self):
        """
        启动动态题目扫描器

        扫描器会作为后台任务运行，定期检查新增题目。
        """
        from chying_agent.contest.dynamic_scanner import DynamicChallengeScanner

        self._dynamic_scanner = DynamicChallengeScanner(
            max_retries=self.max_retries,
            solver_callback=self._solve_dynamic_challenge,
            ctf_dir=self._dynamic_ctf_dir,
            scan_interval=self._dynamic_scan_interval,
        )

        # 注册题目类型配置
        for cat_name, cat_config in self.categories.items():
            self._dynamic_scanner.add_category_config(
                cat_name,
                cat_config.challenges,
                self.concurrency,
            )

        # 启动扫描器
        await self._dynamic_scanner.start()

        log_system_event("[多目标] ✅ 动态扫描器已启动")

    async def _run_category(self, cat_config: CategoryConfig) -> None:
        """
        处理单个类型的所有题目

        使用信号量限制并发数，避免同时创建过多 Orchestrator 实例。
        任务通过 asyncio.Queue + worker 模式调度：只有 concurrency 个 worker 同时运行，
        每个 worker 从队列取任务后才创建 Orchestrator 并执行。

        Args:
            cat_config: 类型配置
        """
        log_system_event(
            f"[{cat_config.name.upper()}] 开始处理，共 {len(cat_config.challenges)} 道题",
        )

        # 使用队列 + worker 模式替代一次性创建所有 task
        queue: asyncio.Queue[Dict] = asyncio.Queue()
        for challenge in cat_config.challenges:
            queue.put_nowait(challenge)

        results: list = []
        results_lock = asyncio.Lock()

        async def worker(_worker_id: int) -> None:
            while True:
                try:
                    challenge = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    result = await self._solve_challenge(challenge, cat_config)
                    async with results_lock:
                        results.append(result)
                except asyncio.CancelledError:
                    raise
                except BaseException as exc:
                    async with results_lock:
                        results.append(exc)
                finally:
                    queue.task_done()

        # 启动 concurrency 个 worker
        worker_tasks = [
            asyncio.create_task(
                worker(i),
                name=f"{cat_config.name}_worker_{i}",
            )
            for i in range(min(self.concurrency, len(cat_config.challenges)))
        ]

        # 等待所有 worker 完成
        await asyncio.gather(*worker_tasks, return_exceptions=True)

        # 统计结果
        for result in results:
            # ⭐ 使用 BaseException 捕获 CancelledError
            # asyncio.CancelledError 是 BaseException，不是 Exception
            if isinstance(result, BaseException):
                cat_config.failed += 1
            elif isinstance(result, dict):
                cat_config.completed += 1
                if result.get("success"):
                    cat_config.success += 1
                elif result.get("cancelled"):
                    # 被取消的任务也计入失败
                    cat_config.failed += 1
                else:
                    cat_config.failed += 1

        log_system_event(
            f"[{cat_config.name.upper()}] ✅ 类型处理完成",
            {
                "成功": cat_config.success,
                "失败": cat_config.failed,
                "总计": len(cat_config.challenges),
            },
        )

    async def _solve_dynamic_challenge(self, challenge: Dict) -> None:
        """
        解决动态发现的新题目

        Args:
            challenge: 题目信息
        """
        category = challenge.get("category", "unknown")

        # 查找对应的 category 配置
        cat_config = self.categories.get(category)
        if not cat_config:
            log_system_event(
                f"[动态扫描] ⚠️ 无法找到类型配置: {category}",
                level=logging.WARNING,
            )
            return

        # 使用该类型的配置执行解题
        result = await self._solve_challenge(challenge, cat_config)

        # 更新统计
        cat_config.completed += 1
        if result and result.get("success"):
            cat_config.success += 1
        else:
            cat_config.failed += 1

    async def _solve_challenge(
        self, challenge: Dict, cat_config: CategoryConfig
    ) -> Dict:
        """
        解决单个题目（带重试）

        信号量在 _run_category 的 worker 模式中隐式控制：
        同时只有 concurrency 个 worker 运行，因此 Orchestrator 创建和
        solve_single_challenge 执行都在并发限制内。

        Args:
            challenge: 题目信息
            cat_config: 类型配置

        Returns:
            解题结果
        """
        from chying_agent.challenge_solver import solve_single_challenge

        challenge_code = challenge["challenge_code"]
        attempt = 0
        result = None
        attempt_history = []

        brain_cfg = getattr(self.config, "brain", None)
        model_name = getattr(brain_cfg, "model", None) or os.getenv("LLM_MODEL") or "inherit"
        strategy_desc = f"{model_name} (Orchestrator 单会话)"

        while attempt <= self.max_retries and self._running:
            if attempt > 0:
                log_system_event(
                    f"[{cat_config.name.upper()}] 重试 {challenge_code}",
                    {"尝试": f"{attempt}/{self.max_retries}", "策略": strategy_desc},
                )

            try:
                result = await solve_single_challenge(
                    challenge=challenge,
                    config=self.config,
                    stats=cat_config.stats,
                    attempt_history=attempt_history if attempt > 0 else None,
                    strategy_description=strategy_desc,
                )

                if result.get("success"):
                    log_system_event(
                        f"[{cat_config.name.upper()}] 🎉 成功: {challenge_code}",
                        {"FLAG": result.get("flag", "N/A")},
                    )
                    return result

                if result:
                    attempt_history.append(
                        {
                            "attempt": attempt + 1,
                            "strategy": strategy_desc,
                            "attempts": result.get("attempts", 0),
                            "failed_methods": [],
                        }
                    )

            except asyncio.CancelledError:
                log_system_event(
                    f"[{cat_config.name.upper()}] 🛑 任务取消: {challenge_code}",
                    level=logging.WARNING,
                )
                raise
            except Exception as e:
                log_system_event(
                    f"[{cat_config.name.upper()}] ⚠️ 异常: {challenge_code} - {str(e)}",
                    level=logging.ERROR,
                )
                attempt_history.append(
                    {
                        "attempt": attempt + 1,
                        "summary": f"异常: {str(e)}",
                        "attempts_count": 0,
                    }
                )

            attempt += 1

        log_system_event(
            f"[{cat_config.name.upper()}] ❌ 失败: {challenge_code}",
            {"尝试次数": attempt},
        )

        return result or {"success": False, "code": challenge_code}

    async def _print_final_status(self):
        """打印最终统计"""
        log_system_event("\n" + "=" * 80)
        log_system_event("📊 多目标并发模式 - 最终统计")
        log_system_event("=" * 80)

        total_success = 0
        total_failed = 0
        total_challenges = 0

        for name, cat in self.categories.items():
            total_success += cat.success
            total_failed += cat.failed
            total_challenges += len(cat.challenges)

            log_system_event(
                f"[{name.upper()}]",
                {
                    "成功": cat.success,
                    "失败": cat.failed,
                    "总计": len(cat.challenges),
                    "成功率": f"{cat.success / len(cat.challenges) * 100:.1f}%"
                    if cat.challenges
                    else "N/A",
                },
            )

        log_system_event("-" * 40)
        log_system_event(
            "[总计]",
            {
                "成功": total_success,
                "失败": total_failed,
                "总计": total_challenges,
                "成功率": f"{total_success / total_challenges * 100:.1f}%"
                if total_challenges
                else "N/A",
            },
        )
        log_system_event("=" * 80)
