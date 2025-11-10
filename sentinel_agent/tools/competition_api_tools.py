"""腾讯云黑客松-智能渗透挑战赛 API 客户端

提供完整的比赛 API 接口封装，包括：
- 获取赛题列表
- 查看提示
- 提交答案

所有接口都包含错误处理和日志记录。
"""

import os
import time
from typing import List, Dict, Optional, Any, Callable
from datetime import datetime
from functools import wraps
import requests
from requests.exceptions import RequestException, Timeout
from langchain_core.tools import tool

from sentinel_agent.common import log_system_event, log_security_event


class CompetitionAPIError(Exception):
    """比赛 API 异常基类"""
    pass


class AuthenticationError(CompetitionAPIError):
    """认证失败异常 (401)"""
    pass


class ValidationError(CompetitionAPIError):
    """参数验证失败异常 (422)"""
    pass


class RateLimitError(CompetitionAPIError):
    """请求频率限制异常 (429)"""
    pass


class BusinessError(CompetitionAPIError):
    """业务逻辑异常 (500)"""
    pass


def retry_on_rate_limit(max_retries: int = 3, base_delay: float = 2.0):
    """
    自动重试装饰器 - 处理请求频率限制、网络错误和临时服务器错误
    
    Args:
        max_retries: 最大重试次数
        base_delay: 基础延迟时间（秒），使用指数退避策略
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                
                except RateLimitError as e:
                    last_exception = e
                    if attempt < max_retries:
                        # 指数退避：2s, 4s, 8s
                        delay = base_delay * (2 ** attempt)
                        log_system_event(
                            f"[API] 请求频率限制，{delay:.1f}秒后重试 "
                            f"(第 {attempt + 1}/{max_retries} 次重试)"
                        )
                        time.sleep(delay)
                    else:
                        log_system_event(f"[API] 已达最大重试次数 ({max_retries})，放弃请求")
                
                except CompetitionAPIError as e:
                    # 502/503 等临时错误可以重试
                    if "502" in str(e) or "503" in str(e) or "504" in str(e):
                        last_exception = e
                        if attempt < max_retries:
                            delay = base_delay * (2 ** attempt)
                            log_system_event(
                                f"[API] 服务器临时错误，{delay:.1f}秒后重试 "
                                f"(第 {attempt + 1}/{max_retries} 次重试): {str(e)}"
                            )
                            time.sleep(delay)
                        else:
                            log_system_event(f"[API] 已达最大重试次数 ({max_retries})，放弃请求")
                    else:
                        # 其他错误（401, 422等）不重试，直接抛出
                        raise
                
                except (requests.exceptions.ConnectionError, Timeout) as e:
                    last_exception = CompetitionAPIError(f"网络连接失败: {str(e)}")
                    if attempt < max_retries:
                        delay = base_delay * (2 ** attempt)
                        log_system_event(
                            f"[API] 网络错误，{delay:.1f}秒后重试 "
                            f"(第 {attempt + 1}/{max_retries} 次重试)"
                        )
                        time.sleep(delay)
                    else:
                        log_system_event(f"[API] 已达最大重试次数 ({max_retries})，放弃请求")
            
            # 所有重试都失败，抛出最后一个异常
            raise last_exception
        
        return wrapper
    return decorator


class CompetitionAPIClient:
    """比赛 API 客户端"""
    
    def __init__(self, base_url: Optional[str] = None, api_token: Optional[str] = None):
        """
        初始化 API 客户端
        
        Args:
            base_url: API 基础 URL，默认从环境变量 COMPETITION_BASE_URL 读取
            api_token: API 认证令牌，默认从环境变量 COMPETITION_API_TOKEN 读取
        """
        self.base_url = base_url or os.getenv("COMPETITION_BASE_URL", "http://x.x.x.x:8000")
        self.api_token = api_token or os.getenv("COMPETITION_API_TOKEN", "")
        
        if not self.api_token:
            log_system_event("[API] 警告: API_TOKEN 未设置，请设置环境变量 COMPETITION_API_TOKEN")
        
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # 请求频率控制（1次/秒）
        self.last_request_time = 0
        self.min_request_interval = 1.0
        
        # 重试配置
        self.max_retries = 3
        self.retry_delay = 2.0
        
        log_system_event(f"[API] 初始化比赛 API 客户端: {self.base_url}")
    
    def _wait_for_rate_limit(self):
        """等待以满足请求频率限制"""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        if time_since_last_request < self.min_request_interval:
            wait_time = self.min_request_interval - time_since_last_request
            log_system_event(f"[API] 请求频率限制，等待 {wait_time:.2f} 秒")
            time.sleep(wait_time)
        
        self.last_request_time = time.time()
    
    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """
        处理 API 响应，统一错误处理
        
        Args:
            response: requests 响应对象
            
        Returns:
            解析后的 JSON 数据
            
        Raises:
            AuthenticationError: 认证失败 (401)
            ValidationError: 参数验证失败 (422)
            RateLimitError: 请求频率限制 (429)
            BusinessError: 业务逻辑异常 (500)
            CompetitionAPIError: 其他异常
        """
        status_code = response.status_code
        
        try:
            data = response.json()
        except ValueError:
            data = {"detail": response.text}
        
        # 成功响应
        if status_code == 200:
            return data
        
        # 错误响应
        error_detail = data.get("detail", "未知错误")
        
        if status_code == 401:
            log_security_event(f"[API] 认证失败: {error_detail}", {"status_code": status_code})
            raise AuthenticationError(f"认证失败: {error_detail}")
        
        elif status_code == 422:
            log_system_event(f"[API] 参数验证失败: {error_detail}")
            raise ValidationError(f"参数验证失败: {error_detail}")
        
        elif status_code == 429:
            log_system_event(f"[API] 请求过于频繁: {error_detail}")
            raise RateLimitError(f"请求过于频繁: {error_detail}")
        
        elif status_code == 500:
            log_system_event(f"[API] 业务异常: {error_detail}")
            raise BusinessError(f"业务异常: {error_detail}")
        
        else:
            log_system_event(f"[API] 未知错误: {status_code} - {error_detail}")
            raise CompetitionAPIError(f"API 错误 ({status_code}): {error_detail}")
    
    @retry_on_rate_limit(max_retries=3, base_delay=2.0)
    def get_challenges(self) -> Dict[str, Any]:
        """
        获取当前阶段赛题列表（带自动重试）
        
        Returns:
            包含当前阶段和赛题列表的字典:
            {
                "current_stage": "debug" | "competition",
                "challenges": [
                    {
                        "challenge_code": str,
                        "difficulty": "easy" | "medium" | "hard",
                        "points": int,
                        "hint_viewed": bool,
                        "solved": bool,
                        "target_info": {
                            "ip": str,
                            "port": List[int]
                        }
                    }
                ]
            }
        """
        self._wait_for_rate_limit()
        
        url = f"{self.base_url}/api/v1/challenges"
        
        log_system_event(f"[API] 获取赛题列表: {url}")
        response = requests.get(url, headers=self.headers, timeout=10)
        data = self._handle_response(response)
        
        log_system_event(
            f"[API] 成功获取赛题列表: 阶段={data.get('current_stage')}, "
            f"题目数={len(data.get('challenges', []))}"
        )
        
        return data
    
    @retry_on_rate_limit(max_retries=3, base_delay=2.0)
    def get_hint(self, challenge_code: str) -> Dict[str, Any]:
        """
        查看指定赛题的提示信息（带自动重试）
        
        Args:
            challenge_code: 赛题唯一标识码
            
        Returns:
            提示信息字典:
            {
                "hint_content": str,
                "penalty_points": int,
                "first_use": bool
            }
        """
        self._wait_for_rate_limit()
        
        url = f"{self.base_url}/api/v1/hint/{challenge_code}"
        
        log_system_event(f"[API] 查看提示: {challenge_code}")
        response = requests.get(url, headers=self.headers, timeout=10)
        data = self._handle_response(response)
        
        log_security_event(
            f"[API] 查看提示成功: {challenge_code}",
            {
                "first_use": data.get("first_use"),
                "penalty_points": data.get("penalty_points"),
                "hint_preview": data.get("hint_content", "")
            }
        )
        
        return data
    
    @retry_on_rate_limit(max_retries=3, base_delay=2.0)
    def submit_answer(self, challenge_code: str, answer: str) -> Dict[str, Any]:
        """
        提交赛题答案（带自动重试）
        
        Args:
            challenge_code: 赛题唯一标识码
            answer: 答案内容（通常为 flag{...} 或 FLAG{...} 格式）
            
        Returns:
            提交结果字典:
            {
                "correct": bool,
                "earned_points": int,
                "is_solved": bool
            }
        """
        self._wait_for_rate_limit()
        
        url = f"{self.base_url}/api/v1/answer"
        payload = {
            "challenge_code": challenge_code,
            "answer": answer
        }
        
        log_system_event(f"[API] 提交答案: {challenge_code}")
        response = requests.post(url, headers=self.headers, json=payload, timeout=10)
        data = self._handle_response(response)
        
        if data.get("correct"):
            log_security_event(
                f"[API] ✓ 答案正确: {challenge_code}",
                {
                    "earned_points": data.get("earned_points"),
                    "is_solved": data.get("is_solved"),
                    "answer": answer
                }
            )
        else:
            log_system_event(f"[API] ✗ 答案错误: {challenge_code}")
        
        return data


# 全局 API 客户端实例
_api_client: Optional[CompetitionAPIClient] = None


def get_api_client() -> CompetitionAPIClient:
    """获取全局 API 客户端实例"""
    global _api_client
    if _api_client is None:
        _api_client = CompetitionAPIClient()
    return _api_client


# ==================== LangChain Tools ====================
# 以下是供 Agent 调用的工具函数


@tool
def get_challenge_list() -> str:
    """
    获取当前阶段的所有赛题信息。
    
    返回当前比赛阶段（调试/正式）以及所有可用赛题的详细信息，包括：
    - 赛题代码
    - 难度等级
    - 分值
    - 目标服务器 IP 和端口
    - 是否已查看提示
    - 是否已解答
    
    Returns:
        格式化的赛题列表字符串（JSON格式）
    """
    try:
        client = get_api_client()
        data = client.get_challenges()
        
        current_stage = data.get("current_stage", "unknown")
        challenges = data.get("challenges", [])
        
        # 转换为更友好的格式
        formatted_challenges = []
        for challenge in challenges:
            target_info = challenge.get('target_info', {})
            formatted_challenges.append({
                "code": challenge.get('challenge_code'),
                "name": f"Challenge {challenge.get('challenge_code')}",
                "type": "web",
                "difficulty": challenge.get('difficulty'),
                "points": challenge.get('points'),
                "url": f"http://{target_info.get('ip')}:{target_info.get('port', [80])[0] if target_info.get('port') else 80}",
                "hint_viewed": challenge.get('hint_viewed'),
                "solved": challenge.get('solved')
            })
        
        # 返回 JSON 格式，方便 Agent 解析
        import json
        return json.dumps({
            "current_stage": current_stage,
            "total": len(formatted_challenges),
            "challenges": formatted_challenges
        }, ensure_ascii=False, indent=2)
        
    except CompetitionAPIError as e:
        return f"获取赛题列表失败: {str(e)}"


@tool
def view_challenge_hint(challenge_code: str) -> str:
    """
    查看指定赛题的提示信息。
    
    注意：查看提示后，成功解题时会扣除一定的惩罚积分。
    每题仅有一个提示，多次调用不会重复扣分。
    
    Args:
        challenge_code: 赛题唯一标识码（如 "debugdemo1"）
        
    Returns:
        提示内容和惩罚信息
    """
    try:
        client = get_api_client()
        data = client.get_hint(challenge_code)
        
        hint_content = data.get("hint_content", "")
        penalty_points = data.get("penalty_points", 0)
        first_use = data.get("first_use", False)
        
        result = []
        if first_use:
            result.append(f"⚠️  首次查看提示，解题成功时将扣除 {penalty_points} 分")
        else:
            result.append(f"ℹ️  已查看过此提示（惩罚分: {penalty_points}）")
        
        result.append(f"\n提示内容:\n{hint_content}")
        
        return "\n".join(result)
        
    except BusinessError as e:
        return f"无法查看提示: {str(e)}"
    except CompetitionAPIError as e:
        return f"查看提示失败: {str(e)}"


@tool
def submit_flag(challenge_code: str, flag: str) -> str:
    """
    提交赛题答案（flag）。
    
    答案格式通常为 flag{...} 或 FLAG{...}，大小写均可。
    每个题目最多支持提交 100 次。
    
    Args:
        challenge_code: 赛题唯一标识码（如 "debugdemo1"）
        flag: 答案内容（如 "flag{e82fba66-3230-4818-8960-800ab47b0ba3}"）
        
    Returns:
        提交结果信息
    """
    try:
        client = get_api_client()
        data = client.submit_answer(challenge_code, flag)
        
        correct = data.get("correct", False)
        earned_points = data.get("earned_points", 0)
        is_solved = data.get("is_solved", False)
        
        if correct:
            if is_solved:
                return f"✓ 答案正确！但该题目之前已解答过，本次不计分。"
            else:
                return f"✓ 答案正确！获得 {earned_points} 分！"
        else:
            return f"✗ 答案错误，请继续尝试。"
        
    except BusinessError as e:
        return f"提交失败: {str(e)}"
    except RateLimitError as e:
        return f"提交过于频繁: {str(e)}"
    except CompetitionAPIError as e:
        return f"提交答案失败: {str(e)}"


# 导出所有工具
COMPETITION_TOOLS = [
    get_challenge_list,
    view_challenge_hint,
    submit_flag
]


def get_competition_tools() -> List:
    """获取所有比赛相关的工具"""
    return COMPETITION_TOOLS
