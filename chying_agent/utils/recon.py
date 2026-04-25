"""
自动信息收集模块
================

在 Agent 开始决策前，自动执行基础信息收集，避免盲猜。

增强功能:
- ⭐ 自动检测和提取 HTML 表单字段
- ⭐ 提取页面核心文本内容（链接、描述、下载链接等）
"""
import re
import requests
from typing import Dict, Optional
from chying_agent.common import log_system_event


def _get_with_retry(
    url: str,
    *,
    timeout: int,
    max_retries: int = 3,
):
    """发送 GET 请求，失败时自动重试。

    语义与用户预期保持一致：首次请求失败后，最多再重试 `max_retries` 次。
    """
    import time

    for attempt in range(max_retries + 1):
        try:
            return requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
        except requests.exceptions.RequestException as e:
            if attempt >= max_retries:
                raise

            retry_delay = attempt + 1
            log_system_event(
                f"[自动侦察] 请求失败，准备重试",
                {
                    "url": url,
                    "attempt": attempt + 1,
                    "max_retries": max_retries,
                    "retry_delay_seconds": retry_delay,
                    "error": str(e),
                },
            )
            time.sleep(retry_delay)


def auto_recon_web_target(target_ip: str, target_port: int, timeout: int = 10, url: Optional[str] = None) -> Dict[str, any]:
    """
    自动对 Web 目标进行基础信息收集

    增强功能:
    - ⭐ 自动检测 HTML 表单并提取字段

    Args:
        target_ip: 目标 IP
        target_port: 目标端口
        timeout: 请求超时时间（秒）
        url: 完整的目标 URL（可选，传入时直接使用，保留原始 scheme 和路径）

    Returns:
        包含收集到的信息的字典：
        {
            "success": bool,
            "url": str,
            "status_code": int,
            "headers": dict,
            "html_content": str,
            "html_length": int,
            "title": str,
            "forms": list,  # ⭐ 新增：表单信息
            "error": str (如果失败)
        }
    """
    if not url:
        url = f"http://{target_ip}:{target_port}"
    import time
    # 比赛时容器启动有延迟，所以等个 1 秒
    time.sleep(1)
    log_system_event(
        f"[自动侦察] 开始收集目标信息: {url}, timeout: {timeout}",
        {}
    )

    result = {
        "success": False,
        "url": url,
        "status_code": None,
        "headers": {},
        "html_content": "",
        "html_length": 0,
        "title": "",
        "forms": [],  # ⭐ 新增
        "error": None
    }

    try:
        # 发送 GET 请求
        response = _get_with_retry(url, timeout=timeout, max_retries=3)

        result["success"] = True
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)
        result["html_content"] = response.text
        result["html_length"] = len(response.text)

        # 尝试提取 <title>
        import re
        title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
        if title_match:
            result["title"] = title_match.group(1).strip()

        # ⭐ 新增：检测并提取表单字段
        if '<form' in response.text.lower():
            try:
                from chying_agent.utils.web_form_parser import extract_web_form_fields

                # 提取所有表单（最多 3 个）
                form_count = response.text.lower().count('<form')
                for i in range(min(form_count, 3)):
                    form_info = extract_web_form_fields(html=response.text, form_index=i)
                    if not form_info.get('error'):
                        result["forms"].append(form_info)

                log_system_event(
                    f"[自动侦察] 🔍 检测到 {len(result['forms'])} 个表单",
                    {"forms": result["forms"]}
                )
            except Exception as e:
                log_system_event(
                    f"[自动侦察] ⚠️ 表单提取失败（非致命错误）",
                    {"error": str(e)}
                )

        log_system_event(
            f"[自动侦察] ✅ 成功获取目标信息",
            {
                "status_code": result["status_code"],
                "content_length": result["html_length"],
                "title": result["title"] if result["title"] else "无标题",
                "server": result["headers"].get("Server", "未知"),
                "content_type": result["headers"].get("Content-Type", "未知"),
                "forms_detected": len(result["forms"]),
                "text_length": len(response.text)
            }
        )

    except requests.exceptions.Timeout:
        result["error"] = f"请求超时（{timeout}秒）"
        log_system_event(
            f"[自动侦察] ⏱️ 请求超时: {url}",
            {"timeout": timeout}
        )
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"连接失败: {str(e)}"
        log_system_event(
            f"[自动侦察] ❌ 连接失败: {url}",
            {"error": str(e)}
        )
    except Exception as e:
        result["error"] = f"未知错误: {str(e)}"
        log_system_event(
            f"[自动侦察] ⚠️ 未知错误: {url}",
            {"error": str(e)}
        )

    return result


# ── 页面核心内容提取（给 LLM 看的精华部分）──────────────────────

# 需要整段移除的标签（含内容）
_STRIP_TAGS_RE = re.compile(
    r'<(script|style|svg|noscript|head)[\s>].*?</\1>',
    re.IGNORECASE | re.DOTALL,
)
# HTML 标签
_TAG_RE = re.compile(r'<[^>]+>')
# 连续空行 → 单空行
_MULTI_NEWLINE_RE = re.compile(r'\n{3,}')

# 纯资源类 href，提取链接时跳过（字体、图片、CSS 对解题无信息量）
_STATIC_ASSET_RE = re.compile(
    r'fonts\.googleapis\.com|\.woff|\.ttf|\.eot|\.ico$',
    re.IGNORECASE,
)


def _extract_page_essentials(html: str, max_text_chars: int = 2000) -> str:
    """从 HTML 中提取 LLM 需要的核心信息：链接、URI/API 路径、下载链接、页面文字。

    不使用任何第三方 HTML 解析库，纯正则，避免额外依赖。
    返回结构化文本，直接可嵌入 prompt。
    """
    parts: list[str] = []

    # 1) 所有 <a href="..."> 链接（外部 + 相对路径）
    links: list[tuple[str, str]] = []
    for m in re.finditer(
        r'<a\b[^>]*\bhref=["\']([^"\'#][^"\']*)["\'][^>]*>(.*?)</a>',
        html, re.IGNORECASE | re.DOTALL,
    ):
        href, text = m.group(1), _TAG_RE.sub('', m.group(2)).strip()
        if _STATIC_ASSET_RE.search(href):
            continue
        if not text or len(text) > 120:
            text = href
        links.append((href, text))
    if links:
        seen = set()
        deduped = []
        for href, text in links:
            if href not in seen:
                seen.add(href)
                deduped.append((href, text))
        if deduped:
            parts.append("**Links:**")
            for href, text in deduped[:30]:
                parts.append(f"- [{text}]({href})")

    # 2) JS/HTML 中的 API 路径和 WebSocket 端点
    api_paths: set[str] = set()
    # fetch("/path") / fetch('/path') / fetch(`/path`)
    for m in re.finditer(r'''fetch\s*\(\s*["`']([^"'`]+)["`']''', html):
        api_paths.add(m.group(1))
    # URL 字符串赋值: "https://..." 或 "/api/..."
    for m in re.finditer(r'''["'](https?://[^"']+|/api/[^"']+|/ws/[^"']+)['"]\s*[;,)]''', html):
        api_paths.add(m.group(1))
    # WebSocket: wss:// or ws://
    for m in re.finditer(r'''["`'](wss?://[^"'`]+)["`']''', html):
        api_paths.add(m.group(1))
    if api_paths:
        parts.append("**API/Endpoints:**")
        for p in sorted(api_paths):
            parts.append(f"- `{p}`")

    # 2) 下载链接（<a ... download ...>）
    downloads: list[tuple[str, str]] = []
    for m in re.finditer(
        r'<a\b[^>]*\bdownload\b[^>]*\bhref=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        html, re.IGNORECASE | re.DOTALL,
    ):
        href, text = m.group(1), _TAG_RE.sub('', m.group(2)).strip()
        downloads.append((href, text or href))
    # 反向匹配 href 在 download 前面的情况
    for m in re.finditer(
        r'<a\b[^>]*\bhref=["\']([^"\']+)["\'][^>]*\bdownload\b[^>]*>(.*?)</a>',
        html, re.IGNORECASE | re.DOTALL,
    ):
        href, text = m.group(1), _TAG_RE.sub('', m.group(2)).strip()
        downloads.append((href, text or href))
    if downloads:
        seen_dl = set()
        parts.append("**Downloads:**")
        for href, text in downloads:
            if href not in seen_dl:
                seen_dl.add(href)
                parts.append(f"- [{text}]({href})")

    # 3) 页面纯文本（去掉 script/style/svg/nav，保留可读文字）
    cleaned = _STRIP_TAGS_RE.sub('', html)
    # 也去掉 <nav>...</nav>（导航栏通常是重复噪音）
    cleaned = re.sub(r'<nav[\s>].*?</nav>', '', cleaned, flags=re.IGNORECASE | re.DOTALL)
    cleaned = _TAG_RE.sub(' ', cleaned)
    # HTML entities
    for ent, ch in [('&amp;', '&'), ('&lt;', '<'), ('&gt;', '>'),
                     ('&quot;', '"'), ('&#39;', "'"), ('&nbsp;', ' '),
                     ('&mdash;', '—'), ('&ndash;', '–')]:
        cleaned = cleaned.replace(ent, ch)
    # 每行 strip，丢弃空行和纯空白短行（< 3 字符）
    lines = []
    for line in cleaned.splitlines():
        line = line.strip()
        if len(line) >= 3:
            lines.append(line)
    text = "\n".join(lines)
    # 压缩连续重复行
    text = _MULTI_NEWLINE_RE.sub('\n\n', text)

    if text:
        truncated = text[:max_text_chars]
        if len(text) > max_text_chars:
            truncated += f"\n... (truncated, total {len(text)} chars)"
        parts.append(f"**Page text:**\n{truncated}")

    return "\n".join(parts)


def format_recon_result_for_llm(recon_result: Dict) -> str:
    """
    将侦察结果格式化为适合 LLM 阅读的文本

    增强功能:
    - ⭐ 自动展示提取的表单字段

    Args:
        recon_result: auto_recon_web_target 的返回结果

    Returns:
        格式化的文本
    """
    if not recon_result["success"]:
        return f"""
## Automated Reconnaissance Results

**Target unreachable**: {recon_result['url']}
- Error: {recon_result['error']}
- Suggestion: Check if target is online, or try other ports
"""

    # 提取关键响应头
    headers = recon_result["headers"]
    key_headers = {
        "Server": headers.get("Server", "N/A"),
        "Content-Type": headers.get("Content-Type", "N/A"),
        "X-Powered-By": headers.get("X-Powered-By", "N/A"),
        "Set-Cookie": headers.get("Set-Cookie", "N/A"),
    }

    # ⭐ 新增：格式化表单信息
    forms_section = ""
    if recon_result.get("forms"):
        forms_section = "\n### Detected Forms\n\n"
        for idx, form in enumerate(recon_result["forms"], 1):
            forms_section += f"**Form {idx}**:\n"
            forms_section += f"- Action: `{form['action']}` (Method: {form['method']})\n"
            forms_section += f"- Fields: {len(form['fields'])}\n"

            # 列出所有字段
            if form['fields']:
                forms_section += "- Field list:\n"
                for field_name, field_info in form['fields'].items():
                    hidden_tag = " [HIDDEN]" if field_info['hidden'] else ""
                    required_tag = " *" if field_info['required'] else ""
                    value_preview = f" (default: '{field_info['value']}')" if field_info['value'] else ""
                    forms_section += f"  - `{field_name}` ({field_info['type']}){hidden_tag}{required_tag}{value_preview}\n"

            forms_section += "\n"

        forms_section += """**Important**:
- All [HIDDEN] fields must be included when submitting, even if they have default values
- For multi-step auth, use `extract_web_form_fields` to extract all fields
- Example:
  ```python
  # Correct approach
  form_info = extract_web_form_fields(resp1.text)
  data = {k: v['value'] for k, v in form_info['fields'].items()}
  data['password'] = 'test'  # Modify needed fields
  resp2 = requests.post(url, data=data)
  ```

"""

    # ⭐ 新增：提取页面核心内容（链接、下载链接、正文摘要）
    page_essentials = ""
    if recon_result.get("html_content"):
        extracted = _extract_page_essentials(recon_result["html_content"])
        if extracted:
            page_essentials = f"\n### Page Content\n{extracted}\n"

    return f"""
## Automated Reconnaissance Results

**Target URL**: {recon_result['url']}
**Status Code**: {recon_result['status_code']}
**Page Title**: {recon_result['title'] if recon_result['title'] else "N/A"}

### Response Headers
```
Server: {key_headers['Server']}
Content-Type: {key_headers['Content-Type']}
X-Powered-By: {key_headers['X-Powered-By']}
Set-Cookie: {key_headers['Set-Cookie']}
```
{forms_section}{page_essentials}
---
**Note**: The above is auto-collected baseline info. Use it to plan your attack strategy — avoid blind guessing.
"""
