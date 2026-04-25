"""Cookie 缓存 -- 自动缓存浏览器页面的 cookie 供 WSS 连接使用"""

import logging
import re
from urllib.parse import urlparse

_logger = logging.getLogger(__name__)

# 全局缓存：{hostname: cookie_string}
_cache: dict[str, str] = {}

# 追踪当前页面 URL（从 navigate_page/new_page 结果中提取）
_current_page_url: str = ""


def set_current_page_url(url: str) -> None:
    """记录当前页面 URL（由 PostToolUse hook 在 navigate_page 成功时调用）"""
    global _current_page_url
    _current_page_url = url


def get_current_page_hostname() -> str:
    """获取当前页面的 hostname"""
    if not _current_page_url:
        return ""
    return urlparse(_current_page_url).hostname or ""


def put(hostname: str, cookie_str: str) -> None:
    """写入或合并 cookie（新 cookie 覆盖同名旧 cookie）"""
    if not hostname or not cookie_str:
        return
    existing = _cache.get(hostname, "")
    if existing:
        merged = _parse_cookie_dict(existing)
        merged.update(_parse_cookie_dict(cookie_str))
        _cache[hostname] = "; ".join(f"{k}={v}" for k, v in merged.items())
    else:
        _cache[hostname] = cookie_str
    _logger.info("Cookie cache updated for %s (%d cookies)", hostname, len(_cache[hostname].split(";")))


def get(hostname: str) -> str:
    """按域名查找 cookie，返回空字符串表示未命中"""
    return _cache.get(hostname, "")


def get_for_url(url: str) -> str:
    """从 URL 提取 hostname 后查找 cookie"""
    hostname = urlparse(url).hostname or ""
    return get(hostname)


def clear() -> None:
    """清空缓存"""
    _cache.clear()


def _parse_cookie_dict(cookie_str: str) -> dict[str, str]:
    """解析 'k1=v1; k2=v2' 为 dict"""
    result: dict[str, str] = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
    return result


# --- 工具结果解析 ---

_COOKIE_PATTERN = re.compile(r"^[\w\-.]+=[\w\-._~+/]", re.ASCII)


def looks_like_cookies(text: str) -> bool:
    """判断文本是否像 cookie 字符串（key=value[; key=value]...）"""
    text = text.strip().strip('"').strip("'")
    if not text or len(text) > 4096:
        return False
    parts = [p.strip() for p in text.split(";") if p.strip()]
    if not parts:
        return False
    return all(_COOKIE_PATTERN.match(p) for p in parts)


def extract_cookies_from_network_response(text: str) -> tuple[str, str]:
    """从 get_network_request 的结果中提取 Cookie 头和对应 URL。

    Returns:
        (cookie_string, hostname) -- 提取失败返回 ("", "")
    """
    cookie_match = re.search(r"(?:^|\n)\s*Cookie:\s*(.+?)(?:\n|$)", text, re.IGNORECASE)
    url_match = re.search(r"(?:^|\n)\s*(?:URL|Request URL):\s*(https?://\S+)", text, re.IGNORECASE)
    if not cookie_match:
        return "", ""
    cookie_str = cookie_match.group(1).strip()
    hostname = ""
    if url_match:
        hostname = urlparse(url_match.group(1)).hostname or ""
    return cookie_str, hostname
