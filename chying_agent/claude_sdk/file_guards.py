"""
文件读取保护模块

提供文件读取前的检查功能，防止大文件或二进制文件浪费 token。
用于 Claude SDK Hook 中拦截不当的文件读取操作。
"""

import os
from typing import Dict, Any, Optional


# 文件大小阈值（超过此大小的文件需要拦截）
FILE_SIZE_THRESHOLD_KB = 50  # 50KB — 防止大文件吃掉 context
FILE_SIZE_THRESHOLD_BYTES = FILE_SIZE_THRESHOLD_KB * 1024

# 二进制文件扩展名（这些文件不应该直接读取）
BINARY_EXTENSIONS = (
    # 图片
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".bmp",
    ".tiff",
    ".ico",
    ".svg",
    # 音视频
    ".mp3",
    ".mp4",
    ".wav",
    ".avi",
    ".mkv",
    ".flv",
    ".mov",
    ".ogg",
    ".flac",
    # 压缩包
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    # 可执行文件
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".elf",
    # 文档
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    # 数据库
    ".db",
    ".sqlite",
    ".sqlite3",
    # 其他二进制
    ".pyc",
    ".class",
    ".o",
    ".a",
    ".lib",
)


def get_file_metadata(file_path: str) -> Dict[str, Any]:
    """
    获取文件元信息

    Args:
        file_path: 文件路径

    Returns:
        文件元信息字典，包含：
        - exists: 文件是否存在
        - size_bytes: 文件大小（字节）
        - size_human: 人类可读的文件大小
        - extension: 文件扩展名
        - is_binary: 是否是二进制文件
        - mime_type: MIME 类型
        - modified_time: 修改时间
    """
    from datetime import datetime

    metadata = {
        "exists": False,
        "size_bytes": 0,
        "size_human": "0 B",
        "extension": "",
        "is_binary": False,
        "mime_type": "unknown",
        "modified_time": None,
    }

    try:
        if not os.path.exists(file_path):
            return metadata

        metadata["exists"] = True
        file_stat = os.stat(file_path)
        size = file_stat.st_size
        metadata["size_bytes"] = size

        # 人类可读的大小
        if size >= 1024 * 1024:
            metadata["size_human"] = f"{size / (1024 * 1024):.2f} MB"
        elif size >= 1024:
            metadata["size_human"] = f"{size / 1024:.2f} KB"
        else:
            metadata["size_human"] = f"{size} B"

        # 扩展名
        ext = os.path.splitext(file_path)[1].lower()
        metadata["extension"] = ext

        # 是否是二进制文件
        metadata["is_binary"] = ext in BINARY_EXTENSIONS

        # 修改时间
        mtime = file_stat.st_mtime
        metadata["modified_time"] = datetime.fromtimestamp(mtime).isoformat()

        # 尝试获取 MIME 类型
        try:
            import mimetypes

            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type:
                metadata["mime_type"] = mime_type
        except Exception:
            pass

    except Exception as e:
        metadata["error"] = str(e)

    return metadata


def check_file_read(tool_name: str, tool_input: Dict[str, Any]) -> Optional[str]:
    """
    检查文件读取操作，对大文件或二进制文件进行拦截

    Args:
        tool_name: 工具名称
        tool_input: 工具参数

    Returns:
        如果需要拦截，返回拒绝原因（包含替代建议）；否则返回 None
    """
    if tool_name != "Read":
        return None

    file_path = tool_input.get("file_path", "")
    if not file_path:
        return None

    # 获取文件元信息
    metadata = get_file_metadata(file_path)

    if not metadata["exists"]:
        return None  # 文件不存在，让 Read 工具自己处理错误

    file_name = os.path.basename(file_path)
    size_bytes = metadata["size_bytes"]
    size_human = metadata["size_human"]
    ext = metadata["extension"]
    is_binary = metadata["is_binary"]
    mime_type = metadata["mime_type"]

    # 二进制文件：始终拦截
    if is_binary:
        return _build_binary_file_message(file_path, file_name, size_human, mime_type, ext, metadata)

    # 大文件：超过阈值时拦截
    # 但如果指定了 limit 参数且 ≤ 100 行，允许部分读取（不会爆 context）
    if size_bytes > FILE_SIZE_THRESHOLD_BYTES:
        read_limit = tool_input.get("limit")
        if read_limit is not None and isinstance(read_limit, (int, float)) and read_limit <= 100:
            return None  # 带 limit 的小范围读取，放行
        return _build_large_file_message(file_path, file_name, size_human, mime_type, ext, metadata)

    # 文件大小在阈值内，允许读取
    return None


def _build_binary_file_message(
    file_path: str,
    file_name: str,
    size_human: str,
    mime_type: str,
    ext: str,
    metadata: Dict[str, Any],
) -> str:
    """构建二进制文件拦截消息"""
    msg = (
        f"Binary file blocked: {file_name} ({size_human}, {mime_type})\n"
        f"Use exec to analyze: "
        f"file \"{file_path}\", strings \"{file_path}\" | head -100, "
        f"xxd \"{file_path}\" | head -20"
    )
    return msg


def _build_large_file_message(
    file_path: str,
    file_name: str,
    size_human: str,
    mime_type: str,
    ext: str,
    metadata: Dict[str, Any],
) -> str:
    """构建大文件拦截消息"""
    return (
        f"⚠️ File too large to Read: {file_name} ({size_human}, threshold {FILE_SIZE_THRESHOLD_KB}KB)\n"
        f"Reading large files wastes context tokens and may cause context overflow.\n"
        f"Use Grep to search for specific keywords instead:\n"
        f"  Grep(pattern=\"keyword\", path=\"{file_path}\", output_mode=\"content\", -C=3)\n"
        f"This returns only the relevant lines with context, saving 90%+ tokens."
    )


__all__ = [
    "FILE_SIZE_THRESHOLD_KB",
    "FILE_SIZE_THRESHOLD_BYTES",
    "BINARY_EXTENSIONS",
    "get_file_metadata",
    "check_file_read",
]
