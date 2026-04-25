"""HackTheBox CTF 适配器 — 直接调用 HTB MCP 工具，不做任何映射

工具清单 (HTB MCP):
  list_ctf_events()                    → 列出所有 CTF 事件
  retrieve_ctf(ctf_id)                 → 获取事件详情 + challenges
  start_container(challenge_id)        → 启动容器
  stop_container(challenge_id)         → 停止容器
  container_status(challenge_id)       → 查询容器状态
  submit_flag(challenge_id, flag)      → 提交 flag
  get_download_link(challenge_id)      → 获取附件下载链接
  retrieve_ctf_scores(ctf_id)          → 排行榜
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from mcp.client.streamable_http import streamable_http_client
from mcp.client.session import ClientSession

from ..common import log_system_event
from .base import BaseCTFRunner


# ==================== 通用 MCP 连接层 ====================


class MCPToolMapper:
    """通用 MCP 连接 + 调用（所有 MCP 平台共用，不含业务逻辑）"""

    def __init__(self, server_url: str, headers: Optional[dict] = None):
        self._server_url = server_url
        self._headers = headers or {}
        self._tools: set[str] = set()
        self._session: Optional[ClientSession] = None
        self._cm_transport: Any = None
        self._cm_session: Any = None

    async def connect(self):
        http_client = httpx.AsyncClient(
            headers=self._headers,
            timeout=httpx.Timeout(30.0, read=300.0),
        )
        self._cm_transport = streamable_http_client(
            self._server_url, http_client=http_client
        )
        read_stream, write_stream, _ = await self._cm_transport.__aenter__()

        self._cm_session = ClientSession(read_stream, write_stream)
        self._session = await self._cm_session.__aenter__()
        init_result = await self._session.initialize()

        log_system_event(
            f"[MCP] 已连接: {init_result.serverInfo.name}",
            {"version": init_result.serverInfo.version},
        )

        tools_result = await self._session.list_tools()
        for tool in tools_result.tools:
            self._tools.add(tool.name)
        log_system_event(
            f"[MCP] 发现 {len(self._tools)} 个工具",
            {"tools": sorted(self._tools)},
        )

    async def call(self, tool_name: str, **kwargs) -> str:
        """调用 MCP 工具，返回文本"""
        if not self._session:
            raise RuntimeError("未连接 MCP server")
        result = await self._session.call_tool(name=tool_name, arguments=kwargs)
        texts = [b.text for b in result.content if hasattr(b, "text")]
        combined = "\n".join(texts)
        if result.isError:
            raise RuntimeError(f"MCP tool error [{tool_name}]: {combined}")
        return combined

    def has_tool(self, name: str) -> bool:
        return name in self._tools

    async def close(self):
        for cm in (self._cm_session, self._cm_transport):
            if cm:
                try:
                    await cm.__aexit__(None, None, None)
                except Exception:
                    pass


# ==================== HTB 适配器 ====================


class HTBCTFRunner(BaseCTFRunner):
    """HackTheBox CTF 平台 — 直接调用 HTB MCP 工具名和参数名"""

    def __init__(
        self,
        server_url: str,
        agent_token: str,
        ctf_id: Optional[int] = None,
        **kwargs,
    ):
        domain = urlparse(server_url).hostname or "htb"
        super().__init__(work_dir_name=domain, **kwargs)
        self._mapper = MCPToolMapper(
            server_url,
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        self._ctf_id = ctf_id

    async def run(self):
        """connect → run → close"""
        await self._mapper.connect()
        try:
            await super().run()
        finally:
            await self._mapper.close()

    # ---------- 子类实现 ----------

    async def discover_challenges(self) -> list[dict]:
        """list_ctf_events → 选比赛 → (auto join) → retrieve_ctf → challenges"""
        events_raw = await self._mapper.call("list_ctf_events")
        events = json.loads(events_raw)

        event = self._select_event(events)
        if not event:
            return []

        event_id = event["id"]
        event_name = event.get("name", "?")
        log_system_event(
            f"[HTB] 选中比赛: {event_name} (id={event_id})"
        )

        # 自动加入比赛（如果还没 join）
        if not event.get("canPlay"):
            await self._auto_join(event)

        ctf_raw = await self._mapper.call("retrieve_ctf", ctf_id=event_id)
        ctf_data = json.loads(ctf_raw)

        # 检查 API 错误
        if isinstance(ctf_data, dict) and "error" in ctf_data:
            log_system_event(
                f"[HTB] retrieve_ctf 失败: {ctf_data['error']}",
                level=logging.ERROR,
            )
            return []

        challenges = self._extract_challenges(ctf_data)
        log_system_event(f"[HTB] 获取到 {len(challenges)} 道题目")
        return challenges

    async def _auto_join(self, event: dict) -> None:
        """自动加入比赛: retrieve_my_teams → join_ctf_event"""
        event_id = event["id"]
        try:
            teams_raw = await self._mapper.call("retrieve_my_teams")
            teams = json.loads(teams_raw)
            if not teams:
                log_system_event("[HTB] 无可用队伍，无法自动加入")
                return

            # 用第一个队伍（通常是自建的 AI 队伍）
            team_id = teams[0]["id"]
            log_system_event(
                f"[HTB] 尝试加入比赛: ctf={event_id} team={team_id}"
            )
            raw = await self._mapper.call(
                "join_ctf_event",
                ctf_id=event_id,
                team_id=team_id,
                consent=True,
            )
            result = json.loads(raw) if raw.strip().startswith("{") else {"message": raw}
            if "error" in result:
                log_system_event(
                    f"[HTB] 加入失败: {result['error']}",
                    level=logging.WARNING,
                )
            else:
                log_system_event(f"[HTB] 成功加入比赛")
        except Exception as e:
            log_system_event(
                f"[HTB] 自动加入异常: {e}", level=logging.WARNING,
            )

    async def start_challenge(self, challenge: dict) -> Optional[str]:
        ch_id = challenge["id"]
        try:
            raw = await self._mapper.call("start_container", challenge_id=ch_id)
            log_system_event(f"[HTB] start_container({ch_id}): {raw[:200]}")

            url = self._extract_url(raw)
            if url:
                return url

            # 轮询 container_status 等待 URL
            if self._mapper.has_tool("container_status"):
                for _ in range(15):
                    await asyncio.sleep(3)
                    status_raw = await self._mapper.call(
                        "container_status", challenge_id=ch_id,
                    )
                    url = self._extract_url(status_raw)
                    if url:
                        return url

            return None
        except Exception as e:
            log_system_event(
                f"[HTB] start_container 失败: {e}", level=logging.ERROR,
            )
            return None

    async def stop_challenge(self, challenge: dict) -> None:
        try:
            await self._mapper.call("stop_container", challenge_id=challenge["id"])
        except Exception as e:
            log_system_event(
                f"[HTB] stop_container 失败: {e}", level=logging.WARNING,
            )

    async def submit_flag(self, challenge: dict, flag: str) -> bool:
        raw = await self._mapper.call(
            "submit_flag", challenge_id=challenge["id"], flag=flag,
        )
        log_system_event(f"[HTB] submit_flag: {raw[:200]}")
        return any(
            kw in raw.lower()
            for kw in ("correct", "accepted", "solved", "success")
        )

    async def download_attachments(self, challenge: dict, work_dir: Path) -> None:
        if not self._mapper.has_tool("get_download_link"):
            return

        ch_id = challenge["id"]
        try:
            raw = await self._mapper.call("get_download_link", challenge_id=ch_id)
            urls = re.findall(r'https?://\S+', raw)

            async with httpx.AsyncClient(
                timeout=60, headers=self._mapper._headers,
            ) as client:
                for url in urls:
                    filename = url.split("/")[-1].split("?")[0]
                    if not filename:
                        continue
                    dest = work_dir / filename
                    if dest.exists():
                        continue
                    resp = await client.get(url, follow_redirects=True)
                    resp.raise_for_status()
                    dest.write_bytes(resp.content)
                    log_system_event(f"[HTB] 下载附件: {filename}")
        except Exception as e:
            log_system_event(
                f"[HTB] 附件下载失败: {e}", level=logging.WARNING,
            )

    async def get_hint(self, challenge: dict) -> str:
        # HTB 当前 MCP 无 hint 工具
        return "HTB 平台暂不支持 hint"

    # ---------- HTB 特有逻辑 ----------

    def _select_event(self, events: list[dict]) -> Optional[dict]:
        """选择比赛: 指定 ctf_id > Ongoing+canPlay > Ongoing+MCP > 第一个"""
        if self._ctf_id:
            for e in events:
                if e.get("id") == self._ctf_id:
                    return e
            log_system_event(
                f"[HTB] ctf_id={self._ctf_id} 未找到", level=logging.ERROR,
            )
            return None

        # 自动选择
        best = None
        best_score = -1
        for e in events:
            if (e.get("status") or "").lower() != "ongoing":
                continue
            score = 0
            if e.get("canPlay"):
                score += 100
            if e.get("hasJoined"):
                score += 50
            if e.get("mcp_access_mode") in ("only_mcp", "both"):
                score += 30
            if score > best_score:
                best_score = score
                best = e

        return best or (events[0] if events else None)

    @staticmethod
    def _extract_challenges(ctf_data) -> list[dict]:
        """从 retrieve_ctf 返回中提取题目列表"""
        if isinstance(ctf_data, list):
            return ctf_data
        if isinstance(ctf_data, dict):
            for key in ("challenges", "data", "items"):
                if key in ctf_data and isinstance(ctf_data[key], list):
                    return ctf_data[key]
        return []
