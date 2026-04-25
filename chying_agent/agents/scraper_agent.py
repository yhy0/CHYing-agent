"""CTF 平台题目爬取 Agent 系统提示词。

Prompt loaded from prompts/scraper.md.
"""

from ..prompts import load_prompt

SCRAPER_AGENT_SYSTEM_PROMPT = load_prompt("scraper.md")

SCRAPER_BATCH_PROMPT = """\
请从 CTF 平台爬取 [{category}] 分类下未解出的题目，最多提取 {limit} 个。

平台 URL: {platform_url}
目标分类: {category}
最多提取: {limit} 道题目
附件下载目录: {work_dir}

<workflow>
1. take_snapshot 查看当前页面，如果不在平台页面则 navigate_page 到上述 URL
2. 点击目标分类 [{category}] 标签
3. take_snapshot 获取当前页面的题目列表
4. 跳过所有已标记为 solved/已解出的题目，只处理未解出的题目
5. 对每个未解出的题目（已提取够 {limit} 个时立即停止）：
   - 点击题目卡片打开详情
   - take_snapshot 获取详情页
   - 提取: 题目名称、分类、描述、分值、解出次数、附件下载链接、靶机地址、challenge_id
   - 如果有附件，用 Bash wget/curl 下载到 {work_dir}/{{Category}}/{{safe_challenge_name}}/
   - 关闭详情弹窗或返回列表页
6. 如果当前页面的未解出题目不够 {limit} 个，且页面有分页/翻页控件，翻到下一页继续
   重复步骤 3-5 直到提取够 {limit} 个或所有页面都翻完
7. 判断 has_more: 该分类是否还有更多未解出的题目（除本次提取的之外）
8. 输出结构化 JSON 结果
</workflow>

<rules>
- 只提取未解出的题目，跳过平台上已标记为 solved/已解出的题目
- 最多提取 {limit} 个题目，达到上限后立即停止
- 自行处理分页：如果当前页不够，翻页继续找
- has_more 表示该分类是否还有更多未解出题目，用于判断是否需要继续下一轮
- category 归一化为小写: web/pwn/misc/crypto/reverse/forensics
- safe_challenge_name: 中文和特殊字符替换为下划线，转小写
- challenge_id 从页面 URL 或元素属性中提取
- Web 题目的 target_url 从描述或题目页面的链接中提取
- 始终使用 take_snapshot 而不是 take_screenshot 来感知页面
- **禁止启动/创建场景**: 不要点击"获取在线场景"、"开始场景"、"Start Instance"、"Launch"等按钮。
  平台每个用户只能同时存在一个场景，创建新场景会销毁之前的场景。
  如果题目没有已运行的靶机地址，target_url 留空字符串即可，后续解题阶段会自行创建场景。
</rules>
"""

__all__ = ["SCRAPER_AGENT_SYSTEM_PROMPT", "SCRAPER_BATCH_PROMPT"]
