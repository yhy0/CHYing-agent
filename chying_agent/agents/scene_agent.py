"""CTF 平台场景管理 Agent 系统提示词。

Prompt loaded from prompts/scene.md.
"""

from ..prompts import load_prompt

SCENE_MANAGER_SYSTEM_PROMPT = load_prompt("scene.md")

SCENE_MANAGER_PROMPT = """\
请在 CTF 平台上为以下题目启动场景并获取靶机 URL。

平台 URL: {platform_url}
题目名称: {challenge_name}
题目 ID: {challenge_id}

操作步骤:
1. take_snapshot 查看当前页面
2. 如果不在平台页面，navigate_page 到上述平台 URL
3. 找到题目 "{challenge_name}"，点击进入详情
4. 查找并点击"启动场景"或类似按钮
5. 等待场景就绪，提取靶机 URL
6. 输出结构化结果

注意：如果场景已经在运行，直接提取 URL 即可。
"""

SCENE_MANAGER_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "success": {"type": "boolean", "description": "场景是否启动成功"},
        "target_url": {
            "type": "string",
            "description": "靶机 URL (如 http://IP:PORT)",
        },
        "message": {"type": "string", "description": "状态信息或错误原因"},
    },
    "required": ["success", "message"],
}

__all__ = [
    "SCENE_MANAGER_SYSTEM_PROMPT",
    "SCENE_MANAGER_PROMPT",
    "SCENE_MANAGER_OUTPUT_SCHEMA",
]
