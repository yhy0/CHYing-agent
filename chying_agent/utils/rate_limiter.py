"""
请求频率限制器模块
==================

用于控制并发环境中的 LLM API 请求速率，避免触发服务端的频率限制。

实现方案：
- 基于令牌桶（Token Bucket）算法
- 支持多种速率限制策略
- 异步和同步都支持
"""
import asyncio
import time
import logging
from typing import Optional
from chying_agent.common import log_system_event


class RateLimiter:
    """
    基于令牌桶的速率限制器
    
    用途：限制并发请求的速率，避免超过 API 的限制。
    """
    
    def __init__(
        self,
        name: str,
        requests_per_second: float = 2.0,
        burst_size: int = 5
    ):
        """
        初始化速率限制器
        
        Args:
            name: 限制器名称（用于日志）
            requests_per_second: 每秒允许的请求数
            burst_size: 突发请求的最大数量（令牌桶大小）
        """
        self.name = name
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size
        self.tokens = float(burst_size)  # 初始令牌数等于桶大小
        self.last_update_time = time.time()
        self.lock = asyncio.Lock()
        
        log_system_event(
            f"[速率限制] 初始化 {name}",
            {
                "requests_per_second": requests_per_second,
                "burst_size": burst_size
            }
        )
    
    async def acquire(self) -> None:
        """
        异步获取一个请求的许可证（令牌）

        如果没有可用的令牌，会等待直到有令牌可用。
        """
        async with self.lock:
            while self.tokens < 1:
                # 计算需要等待的时间
                time_since_update = time.time() - self.last_update_time
                tokens_earned = time_since_update * self.requests_per_second

                if tokens_earned > 0:
                    self.tokens = min(self.burst_size, self.tokens + tokens_earned)
                    self.last_update_time = time.time()

                if self.tokens < 1:
                    # ⭐ 修复：直接等待完整时间，避免忙等待
                    # 计算需要等待的时间（等到下一个令牌产生）
                    wait_time = (1 - self.tokens) / self.requests_per_second
                    # 原逻辑：await asyncio.sleep(min(wait_time, 0.1))  # 可能循环多次
                    # 新逻辑：直接等待完整时间，减少 CPU 开销
                    await asyncio.sleep(wait_time)

            # 消费一个令牌
            self.tokens -= 1

    def acquire_sync(self) -> None:
        """
        同步获取一个请求的许可证（令牌）

        如果没有可用的令牌，会阻塞直到有令牌可用。
        """
        while self.tokens < 1:
            # 计算需要等待的时间
            time_since_update = time.time() - self.last_update_time
            tokens_earned = time_since_update * self.requests_per_second

            if tokens_earned > 0:
                self.tokens = min(self.burst_size, self.tokens + tokens_earned)
                self.last_update_time = time.time()

            if self.tokens < 1:
                # ⭐ 修复：直接等待完整时间，避免忙等待
                # 计算需要等待的时间（等到下一个令牌产生）
                wait_time = (1 - self.tokens) / self.requests_per_second
                # 原逻辑：time.sleep(min(wait_time, 0.01))  # 可能循环多次
                # 新逻辑：直接等待完整时间，减少 CPU 开销
                time.sleep(wait_time)

        # 消费一个令牌
        self.tokens -= 1


class GlobalRateLimitManager:
    """
    全局速率限制管理器
    
    管理所有 LLM API 的速率限制，确保不会超过总体速率限制。
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """初始化全局限制管理器"""
        if not hasattr(self, 'limiters'):
            self.limiters = {}
            log_system_event("[速率限制] 初始化全局管理器")
    
    def get_limiter(
        self,
        name: str,
        requests_per_second: float = 2.0,
        burst_size: int = 5
    ) -> RateLimiter:
        """
        获取或创建指定的限制器
        
        Args:
            name: 限制器名称
            requests_per_second: 每秒允许的请求数
            burst_size: 突发请求的最大数量
        
        Returns:
            RateLimiter 实例
        """
        if name not in self.limiters:
            self.limiters[name] = RateLimiter(
                name=name,
                requests_per_second=requests_per_second,
                burst_size=burst_size
            )
        return self.limiters[name]
    
    def get_all_limiters(self) -> dict:
        """获取所有限制器"""
        return self.limiters.copy()


# 全局实例
_rate_limit_manager = GlobalRateLimitManager()


def get_rate_limiter(
    name: str,
    requests_per_second: float = 2.0,
    burst_size: int = 5
) -> RateLimiter:
    """
    获取全局速率限制器
    
    Args:
        name: 限制器名称
        requests_per_second: 每秒允许的请求数
        burst_size: 突发请求的最大数量
    
    Returns:
        RateLimiter 实例
    """
    return _rate_limit_manager.get_limiter(
        name=name,
        requests_per_second=requests_per_second,
        burst_size=burst_size
    )
