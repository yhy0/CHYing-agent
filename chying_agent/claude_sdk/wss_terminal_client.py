"""WSS Terminal Client — 直连 Web 终端的 WebSocket 客户端

提供多协议编解码（ttyd/wetty/gotty/k8s/generic）、会话管理、命令执行。
MCP 工具层（mcp_tools.py）调用此模块的 WssSessionManager。
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from enum import Enum

import websockets

_logger = logging.getLogger(__name__)


# ─── Protocol Enum & Auto-detection ─────────────────────────────────────────


class WssProtocol(Enum):
    TTYD = "ttyd"
    WETTY = "wetty"
    GOTTY = "gotty"
    K8S = "k8s"
    GENERIC = "generic"


def auto_detect_protocol(url: str) -> WssProtocol:
    """根据 URL 路径特征推断协议类型"""
    url_lower = url.lower()
    if "/ws/shell" in url_lower or "ttyd" in url_lower:
        return WssProtocol.TTYD
    if "/wetty" in url_lower:
        return WssProtocol.WETTY
    if "/gotty" in url_lower:
        return WssProtocol.GOTTY
    if "/api/v1/" in url_lower and "exec" in url_lower:
        return WssProtocol.K8S
    return WssProtocol.GENERIC


# ─── Protocol Codecs ─────────────────────────────────────────────────────────


class WssCodec:
    """协议编解码基类"""

    def encode_input(self, data: str) -> bytes:
        raise NotImplementedError

    def decode_output(self, msg: bytes | str) -> tuple[str, str]:
        """返回 (msg_type, payload)。msg_type: 'output' | 'title' | 'prefs' | 'unknown'"""
        raise NotImplementedError

    def encode_init(self, rows: int, cols: int) -> bytes | str:
        """连接后发送的初始化帧。默认与 encode_resize 相同，子类可覆盖。"""
        return self.encode_resize(rows, cols)

    def encode_resize(self, rows: int, cols: int) -> bytes | str:
        return json.dumps({"rows": rows, "columns": cols})

    def keepalive_frame(self) -> bytes | str | None:
        return None


class TtydCodec(WssCodec):
    def encode_input(self, data: str) -> bytes:
        return b"0" + data.encode("utf-8")

    def decode_output(self, msg: bytes | str) -> tuple[str, str]:
        data = msg if isinstance(msg, bytes) else msg.encode("utf-8")
        if len(data) == 0:
            return "unknown", ""
        prefix = data[0]
        payload = data[1:].decode("utf-8", errors="replace")
        if prefix == 0x30:  # '0'
            return "output", payload
        if prefix == 0x31:  # '1'
            return "title", payload
        if prefix == 0x32:  # '2'
            return "prefs", payload
        return "unknown", payload

    def encode_init(self, rows: int, cols: int) -> str:
        """ttyd 初始化帧：裸 JSON（无前缀），与后续 resize 的 "1"+JSON 不同"""
        return json.dumps({"columns": cols, "rows": rows})

    def encode_resize(self, rows: int, cols: int) -> bytes:
        payload = json.dumps({"columns": cols, "rows": rows})
        return b"1" + payload.encode("utf-8")

    def keepalive_frame(self) -> str:
        """ttyd 应用层保活：发送 JSON_DATA 帧（TEXT WebSocket frame）。

        必须是 str（而非 bytes），因为 websockets 库对 str 发 TEXT frame、
        对 bytes 发 BINARY frame。GKE Gateway / nginx 等反代的 idle timeout
        只认 TEXT frame 为活跃流量，BINARY frame 不重置 idle 计时器。

        帧内容匹配浏览器原生 keepalive：'{"type":"keepalive"}'，
        ttyd 将其识别为 JSON_DATA 帧（前缀 "{"）并忽略内容，但刷新连接活跃状态。
        """
        return '{"type":"keepalive"}'


class WettyCodec(WssCodec):
    def encode_input(self, data: str) -> bytes:
        return data.encode("utf-8")

    def decode_output(self, msg: bytes | str) -> tuple[str, str]:
        text = msg.decode("utf-8", errors="replace") if isinstance(msg, bytes) else msg
        return "output", text


class GottyCodec(WssCodec):
    """GoTTY 协议编解码器。

    Client -> Server 前缀:
      "1" = INPUT (键盘输入)
      "3" = RESIZE_TERMINAL (JSON {columns, rows})

    Server -> Client 前缀:
      "0" = OUTPUT (终端输出, Base64)
      "4" = SET_WINDOW_TITLE
    """

    def encode_input(self, data: str) -> bytes:
        return ("1" + data).encode("utf-8")

    def decode_output(self, msg: bytes | str) -> tuple[str, str]:
        data = msg if isinstance(msg, bytes) else msg.encode("utf-8")
        if len(data) == 0:
            return "unknown", ""
        prefix = chr(data[0])
        payload = data[1:].decode("utf-8", errors="replace")
        if prefix == "0":
            return "output", payload
        if prefix == "4":
            return "title", payload
        return "unknown", payload

    def encode_resize(self, rows: int, cols: int) -> bytes:
        payload = json.dumps({"columns": cols, "rows": rows})
        return b"3" + payload.encode("utf-8")


class K8sCodec(WssCodec):
    def encode_input(self, data: str) -> bytes:
        return b"\x00" + data.encode("utf-8")

    def decode_output(self, msg: bytes | str) -> tuple[str, str]:
        data = msg if isinstance(msg, bytes) else msg.encode("utf-8")
        if len(data) == 0:
            return "unknown", ""
        channel = data[0]
        payload = data[1:].decode("utf-8", errors="replace")
        if channel == 1:  # stdout
            return "output", payload
        if channel == 2:  # stderr
            return "output", payload
        return "unknown", payload

    def encode_resize(self, rows: int, cols: int) -> bytes:
        payload = json.dumps({"Width": cols, "Height": rows})
        return b"\x04" + payload.encode("utf-8")


class GenericCodec(WssCodec):
    def encode_input(self, data: str) -> bytes:
        return data.encode("utf-8")

    def decode_output(self, msg: bytes | str) -> tuple[str, str]:
        text = msg.decode("utf-8", errors="replace") if isinstance(msg, bytes) else msg
        return "output", text


_CODEC_MAP: dict[WssProtocol, type[WssCodec]] = {
    WssProtocol.TTYD: TtydCodec,
    WssProtocol.WETTY: WettyCodec,
    WssProtocol.GOTTY: GottyCodec,
    WssProtocol.K8S: K8sCodec,
    WssProtocol.GENERIC: GenericCodec,
}


def _strip_ansi(text: str) -> str:
    """去除 ANSI 转义序列"""
    text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z~]", "", text)
    text = re.sub(r"\x1b\][^\x07]*\x07", "", text)
    text = re.sub(r"\x1b[\(\)][A-Z0-9]", "", text)
    text = text.replace("\r", "")
    # 某些 /proc/*/environ 或 ttyd 输出会夹带 NUL/控制字符，若不清理会污染日志和时间线文件。
    text = "".join(
        ch for ch in text
        if ch in ("\n", "\t") or ord(ch) >= 32
    )
    return text


# ─── Session ─────────────────────────────────────────────────────────────────

_DELIM = "__WSS_CMD_END_9f7a__"
_EXIT_MARKER = "__WSS_EXIT_c1a4__"
_KEEPALIVE_INTERVAL = 5  # seconds
_INIT_ROWS = 50
_INIT_COLS = 200
_BANNER_TIMEOUT = 5  # seconds for consuming initial banner
_INPUT_CHUNK_SIZE = 256  # bytes per WebSocket frame for input chunking
_INPUT_CHUNK_DELAY = 0.01  # seconds between chunks (10ms)


_PROBE_MARKER = "__WSS_PROBE_7b3e__"


async def _probe_codec(
    ws: websockets.ClientConnection,
    candidate_codecs: list[tuple[WssProtocol, WssCodec]],
    timeout: float = 8.0,
) -> WssCodec:
    """连接后自动探测正确的 codec。

    依次用候选 codec 的 encode_input 发送 probe 命令，
    检测哪个能收到包含 marker 的输出。

    Args:
        ws: 已建立的 WebSocket 连接（init 帧已发送，banner 已消费）
        candidate_codecs: 要尝试的 (protocol, codec) 列表，按优先级排序
        timeout: 每个候选 codec 的总超时

    Returns:
        探测成功的 codec。如果全部失败，返回 GenericCodec 作为 fallback。
    """
    for proto, codec in candidate_codecs:
        probe_cmd = f"echo {_PROBE_MARKER}\n"
        try:
            await ws.send(codec.encode_input(probe_cmd))
        except Exception:
            continue

        # 收集响应，检查是否包含 marker
        collected = ""
        deadline = asyncio.get_event_loop().time() + timeout
        found = False
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=min(remaining, 3.0))
                msg_type, payload = codec.decode_output(msg)
                if msg_type == "output":
                    collected += payload
                    if _PROBE_MARKER in _strip_ansi(collected):
                        found = True
                        break
            except asyncio.TimeoutError:
                break
            except Exception:
                break

        if found:
            _logger.info("WSS codec probe: %s succeeded", proto.value)
            # 消费残留帧
            for _ in range(3):
                try:
                    await asyncio.wait_for(ws.recv(), timeout=0.2)
                except (asyncio.TimeoutError, Exception):
                    break
            return codec

    _logger.warning("WSS codec probe: all candidates failed, falling back to GenericCodec")
    return GenericCodec()


class SessionState(Enum):
    CONNECTED = "connected"
    DEAD = "dead"
    CLOSED = "closed"


class WssSession:
    """单个 WSS 终端会话"""

    def __init__(self, session_id: str, ws: websockets.ClientConnection, codec: WssCodec):
        self.session_id = session_id
        self.ws = ws
        self.codec = codec
        self.state = SessionState.CONNECTED
        self._keepalive_task: asyncio.Task | None = None
        self._exec_lock = asyncio.Lock()

    async def start_keepalive(self) -> None:
        app_frame = self.codec.keepalive_frame()

        async def _loop():
            try:
                while self.state == SessionState.CONNECTED:
                    await asyncio.sleep(_KEEPALIVE_INTERVAL)
                    if self.state != SessionState.CONNECTED:
                        break
                    # 应用层 keepalive 优先发送（TEXT frame，刷新反代 idle timer）
                    if app_frame is not None:
                        try:
                            await self.ws.send(app_frame)
                        except Exception:
                            _logger.warning("WSS keepalive app frame send failed, marking session dead")
                            self.state = SessionState.DEAD
                            break
                    # WebSocket 协议层 ping（可选，部分代理不转发 pong）
                    try:
                        pong = await self.ws.ping()
                        await asyncio.wait_for(pong, timeout=10)
                    except Exception:
                        # ping 失败不一定代表连接死亡（代理可能吞了 pong），
                        # 只要 app frame 发送成功就继续
                        if app_frame is None:
                            _logger.warning("WSS keepalive ping failed (no app frame fallback), marking session dead")
                            self.state = SessionState.DEAD
                            break
                        else:
                            _logger.debug("WSS keepalive ping failed but app frame succeeded, continuing")
            except Exception:
                self.state = SessionState.DEAD

        self._keepalive_task = asyncio.create_task(_loop())

    async def consume_banner(self) -> str:
        """消费连接后的初始输出（MOTD/prompt），返回清理后的 banner 文本

        使用渐进式超时：首帧等待较长（3s），后续帧用短超时（0.5s）避免阻塞。
        """
        parts: list[str] = []
        first_recv = True
        while True:
            try:
                wait_time = _BANNER_TIMEOUT if first_recv else 0.5
                msg = await asyncio.wait_for(self.ws.recv(), timeout=wait_time)
                first_recv = False
                msg_type, payload = self.codec.decode_output(msg)
                if msg_type == "output":
                    parts.append(payload)
            except asyncio.TimeoutError:
                break
            except Exception:
                self.state = SessionState.DEAD
                break
        return _strip_ansi("".join(parts))

    async def _send_chunked(self, text: str) -> None:
        """分块发送输入文本，模拟终端打字行为。

        将长文本拆分为 _INPUT_CHUNK_SIZE 字节的小块逐帧发送，
        避免单个巨帧导致 ttyd/反代断开连接。
        短文本（<= _INPUT_CHUNK_SIZE）仍然单帧发送，无额外延迟。
        """
        encoded = text.encode("utf-8")
        if len(encoded) <= _INPUT_CHUNK_SIZE:
            await self.ws.send(self.codec.encode_input(text))
            return

        # 按字节分块，但在 UTF-8 字符边界切割
        offset = 0
        while offset < len(encoded):
            end = min(offset + _INPUT_CHUNK_SIZE, len(encoded))
            # 避免在 UTF-8 多字节序列中间切割
            while end < len(encoded) and (encoded[end] & 0xC0) == 0x80:
                end -= 1
            chunk_text = encoded[offset:end].decode("utf-8", errors="replace")
            await self.ws.send(self.codec.encode_input(chunk_text))
            offset = end
            if offset < len(encoded):
                await asyncio.sleep(_INPUT_CHUNK_DELAY)

    async def exec(self, command: str, timeout: int = 30) -> tuple[str, str, int | None]:
        """执行命令，返回 (output, exit_hint, exit_code)

        exit_hint: 'prompt_returned' | 'timeout' | 'session_dead'

        使用 _exec_lock 确保同一会话上的命令串行执行。
        并发调用时后续命令会等待前一个完成，而不是竞争同一个 WebSocket 流。
        """
        if self.state != SessionState.CONNECTED:
            return "", "session_dead", None

        async with self._exec_lock:
            if self.state != SessionState.CONNECTED:
                return "", "session_dead", None
            return await self._exec_inner(command, timeout)

    async def _exec_inner(
        self, command: str, timeout: int
    ) -> tuple[str, str, int | None]:
        """exec 的实际实现（在 _exec_lock 内调用）。"""
        full_cmd = (
            command
            + f" ; __chy_rc=$?; printf '\\n{_EXIT_MARKER}%s\\n' \"$__chy_rc\"; echo {_DELIM}\n"
        )
        try:
            await self._send_chunked(full_cmd)
        except Exception as exc:
            _logger.error(
                "WSS send failed (session=%s, cmd_len=%d, exc_type=%s): %s",
                self.session_id, len(full_cmd), type(exc).__name__, exc,
            )
            self.state = SessionState.DEAD
            return "", "session_dead", None

        output_parts: list[str] = []
        exit_hint = "timeout"
        # 全局截止时间：防止非 output 帧（title/prefs/keepalive）持续到来
        # 导致单帧 wait_for 不断重置而永远不超时的问题
        deadline = asyncio.get_event_loop().time() + timeout

        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                msg = await asyncio.wait_for(
                    self.ws.recv(), timeout=min(remaining, timeout)
                )
                msg_type, payload = self.codec.decode_output(msg)
                if msg_type == "output":
                    output_parts.append(payload)
                    joined = "".join(output_parts)
                    # 先 strip ANSI 再检测 delimiter，避免 \x1b[?2004l 等控制码
                    # 干扰行分割导致误判回显行中的 delimiter 为实际输出
                    if _DELIM in joined:
                        clean = _strip_ansi(joined)
                        for line in clean.split("\n"):
                            stripped = line.strip()
                            # delimiter 作为独立行出现（不是 echo 命令的回显）
                            if stripped == _DELIM:
                                exit_hint = "prompt_returned"
                                break
                        if exit_hint == "prompt_returned":
                            break
            except asyncio.TimeoutError:
                break
            except Exception as exc:
                _logger.error(
                    "WSS recv failed (session=%s, exc_type=%s): %s",
                    self.session_id, type(exc).__name__, exc,
                )
                self.state = SessionState.DEAD
                return _strip_ansi("".join(output_parts)), "session_dead", None

        # 消费可能残留的 prompt 消息（可能跨多帧）
        for _ in range(5):
            try:
                await asyncio.wait_for(self.ws.recv(), timeout=0.15)
            except (asyncio.TimeoutError, Exception):
                break

        raw = "".join(output_parts)
        parsed_output, exit_code = self._parse_output(raw, command)
        return parsed_output, exit_hint, exit_code

    def _parse_output(self, raw: str, command: str) -> tuple[str, int | None]:
        """清理输出：去 ANSI、去命令回显、去 delimiter，并提取 exit code。"""
        clean = _strip_ansi(raw)
        lines = clean.split("\n")
        result: list[str] = []
        past_echo = False
        exit_code: int | None = None

        # 构建回显匹配模式：完整命令 + delimiter echo
        echo_suffix = f" ; __chy_rc=$?; printf '\\n{_EXIT_MARKER}%s\\n' \"$__chy_rc\"; echo {_DELIM}"
        for line in lines:
            stripped = line.strip()
            if stripped == _DELIM:
                break
            if not past_echo:
                # 回显行包含完整命令或 delimiter echo 命令
                if stripped and (echo_suffix in line or "echo " + _DELIM in stripped):
                    past_echo = True
                    continue
                # 也检查命令本身（对于不带 delimiter 的回显）
                if stripped and command.rstrip() == stripped.rstrip():
                    past_echo = True
                    continue
            else:
                result.append(line)

        # 如果从未找到回显行，返回 delimiter 之前的全部内容
        if not past_echo:
            result = []
            for line in lines:
                if line.strip() == _DELIM:
                    break
                result.append(line)

        filtered: list[str] = []
        for line in result:
            stripped = line.strip()
            if stripped.startswith(_EXIT_MARKER):
                maybe_code = stripped[len(_EXIT_MARKER):].strip()
                try:
                    exit_code = int(maybe_code)
                except ValueError:
                    exit_code = None
                continue
            filtered.append(line)

        return "\n".join(filtered).strip(), exit_code

    async def close(self) -> None:
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
        if self.state == SessionState.CONNECTED:
            try:
                await self.ws.close()
            except Exception:
                pass
        self.state = SessionState.CLOSED


# ─── Session Manager ─────────────────────────────────────────────────────────


class WssSessionManager:
    """全局 WSS 会话管理器"""

    def __init__(self):
        self._sessions: dict[str, WssSession] = {}

    async def create(
        self,
        url: str,
        cookie: str,
        protocol: str = "auto",
        origin: str | None = None,
        extra_headers: dict[str, str] | None = None,
        subprotocols: list[str] | None = None,
    ) -> tuple[str, str, str]:
        """创建连接。返回 (session_id, status, banner)

        连接成功后始终自动探测正确的 codec（发送 probe 命令检测响应）。
        protocol 参数（auto/显式指定）仅影响 init 帧格式和候选探测顺序。
        """
        if protocol == "auto":
            hint_proto = auto_detect_protocol(url)
            explicit_protocol = False
        else:
            try:
                hint_proto = WssProtocol(protocol)
                explicit_protocol = True
            except ValueError:
                return "", "failed", f"Unknown protocol: {protocol}"

        session_id, status, banner = await self._try_connect(
            url, hint_proto, cookie, origin, extra_headers, subprotocols,
        )
        if status == "connected":
            return session_id, status, banner

        # 显式指定协议失败时，自动回退到 auto_detect 重试
        if explicit_protocol:
            auto_proto = auto_detect_protocol(url)
            if auto_proto != hint_proto:
                _logger.info(
                    "WSS connect failed with explicit protocol=%s, retrying with auto-detected=%s",
                    protocol, auto_proto.value,
                )
                session_id, status, banner = await self._try_connect(
                    url, auto_proto, cookie, origin, extra_headers, subprotocols,
                )
                if status == "connected":
                    return session_id, status, banner

        return session_id, status, banner

    async def _try_connect(
        self,
        url: str,
        hint_proto: WssProtocol,
        cookie: str,
        origin: str | None,
        extra_headers: dict[str, str] | None,
        subprotocols: list[str] | None,
    ) -> tuple[str, str, str]:
        """尝试用指定协议连接。返回 (session_id, status, banner)"""
        init_codec = _CODEC_MAP[hint_proto]()

        headers: dict[str, str] = {}
        if extra_headers:
            headers.update(extra_headers)
        if cookie:
            headers["Cookie"] = cookie
        if origin:
            headers["Origin"] = origin

        connect_kwargs: dict = {
            "additional_headers": headers,
            "open_timeout": 10,
        }
        if subprotocols:
            connect_kwargs["subprotocols"] = subprotocols

        try:
            ws = await websockets.connect(url, **connect_kwargs)
        except Exception as e:
            return "", "failed", str(e)

        # 发送 init resize 帧
        try:
            await ws.send(init_codec.encode_init(_INIT_ROWS, _INIT_COLS))
        except Exception as e:
            try:
                await ws.close()
            except Exception:
                pass
            return "", "failed", f"Failed to send init resize: {e}"

        # 消费初始 banner（用 init_codec 解码）
        session_id = uuid.uuid4().hex[:12]
        tmp_session = WssSession(session_id, ws, init_codec)
        banner = await tmp_session.consume_banner()

        # 始终探测正确的 codec：hint 协议排第一，然后其他候选
        candidates: list[tuple[WssProtocol, WssCodec]] = []
        candidates.append((hint_proto, init_codec))
        for p, cls in _CODEC_MAP.items():
            if p != hint_proto and p != WssProtocol.K8S:
                candidates.append((p, cls()))
        final_codec = await _probe_codec(ws, candidates, timeout=5.0)

        # 创建正式 session（可能使用探测后不同的 codec）
        session = WssSession(session_id, ws, final_codec)
        session.state = SessionState.CONNECTED
        await session.start_keepalive()

        self._sessions[session_id] = session
        detected_name = next(
            (p.value for p, cls in _CODEC_MAP.items() if isinstance(final_codec, cls)),
            "unknown",
        )
        _logger.info("WSS session created: %s -> %s (codec=%s)", session_id, url, detected_name)
        return session_id, "connected", banner

    def get(self, session_id: str) -> WssSession:
        """获取会话，不存在或已死亡时抛 ValueError"""
        session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(f"Session not found: {session_id}")
        if session.state == SessionState.DEAD:
            raise ValueError(f"Session is dead: {session_id} (reconnect needed)")
        if session.state == SessionState.CLOSED:
            raise ValueError(f"Session is closed: {session_id}")
        return session

    async def close(self, session_id: str) -> str:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return "not_found"
        await session.close()
        _logger.info("WSS session closed: %s", session_id)
        return "closed"

    async def close_all(self) -> None:
        for sid in list(self._sessions.keys()):
            await self.close(sid)
        _logger.info("All WSS sessions closed")


# ─── Per-challenge Session Manager (challenge_code 索引) ─────────────────────

_managers: dict[str, WssSessionManager] = {}
_DEFAULT_KEY = "__default__"


def get_session_manager() -> WssSessionManager:
    """获取当前 challenge 上下文的 session manager（自动创建）。

    使用 challenge_code 作为索引 key，避免 contextvars 在 MCP 工具回调中
    因 asyncio Task 切换导致 session 丢失的问题。
    如果 challenge_code 不可用（单目标模式），使用默认 key。
    """
    try:
        from chying_agent.runtime.context import get_current_challenge_code
        key = get_current_challenge_code() or _DEFAULT_KEY
    except Exception:
        key = _DEFAULT_KEY

    mgr = _managers.get(key)
    if mgr is None:
        mgr = WssSessionManager()
        _managers[key] = mgr
    return mgr


async def cleanup_session_manager(challenge_code: str | None = None) -> None:
    """清理指定 challenge 的 session manager（关闭所有 WSS 连接）。

    在 challenge 结束时调用，防止连接泄漏。
    同时清理 _DEFAULT_KEY 兜底，防止 contextvar 设置失败导致的 key 不匹配泄漏。
    """
    key = challenge_code or _DEFAULT_KEY
    # 清理指定 challenge 的 manager
    mgr = _managers.pop(key, None)
    if mgr is not None:
        await mgr.close_all()
        _logger.info("WSS session manager cleaned up for: %s", key)
    # 兜底：如果 challenge_code 非空，也清理 _DEFAULT_KEY（防止 key 不匹配泄漏）
    if challenge_code and _DEFAULT_KEY in _managers:
        default_mgr = _managers.pop(_DEFAULT_KEY)
        await default_mgr.close_all()
        _logger.info("WSS session manager cleaned up for: %s (fallback)", _DEFAULT_KEY)
