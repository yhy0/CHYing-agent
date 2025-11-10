"""
提示接口调用策略
================

定义何时建议使用提示接口的策略。

核心原则：
- 提示接口会扣分，应作为保底策略
- 基于失败次数、时间消耗、置信度等因素综合判断
- 提供明确的建议，但最终由 LLM 决定
"""
from typing import Dict, Optional
from datetime import datetime, timedelta


class HintStrategy:
    """提示调用策略"""
    
    def __init__(
        self,
        # 失败次数阈值
        failure_threshold_soft: int = 5,   # 软阈值：开始建议
        failure_threshold_hard: int = 10,  # 硬阈值：强烈建议
        
        # 时间阈值
        time_threshold_soft: float = 300.0,   # 5分钟
        time_threshold_hard: float = 600.0,   # 10分钟
        
        # 置信度阈值
        confidence_threshold: float = 30.0,  # 置信度 < 30% 建议提示
        
        # 重复方法阈值
        repeat_method_threshold: int = 3,  # 同一方法失败3次
    ):
        self.failure_threshold_soft = failure_threshold_soft
        self.failure_threshold_hard = failure_threshold_hard
        self.time_threshold_soft = time_threshold_soft
        self.time_threshold_hard = time_threshold_hard
        self.confidence_threshold = confidence_threshold
        self.repeat_method_threshold = repeat_method_threshold
    
    def should_suggest_hint(
        self,
        attempts_count: int,
        elapsed_time: float,
        current_confidence: Optional[float] = None,
        recent_methods: Optional[list] = None
    ) -> Dict[str, any]:
        """
        判断是否建议使用提示
        
        Args:
            attempts_count: 当前尝试次数
            elapsed_time: 已消耗时间（秒）
            current_confidence: 当前置信度（0-100）
            recent_methods: 最近使用的方法列表
        
        Returns:
            字典包含：
            - should_suggest: 是否建议
            - urgency: 紧急程度（none/soft/hard）
            - reasons: 原因列表
            - message: 建议消息
        """
        reasons = []
        urgency = "none"
        
        # 1. 检查失败次数
        if attempts_count >= self.failure_threshold_hard:
            reasons.append(f"已失败 {attempts_count} 次（硬阈值 {self.failure_threshold_hard}）")
            urgency = "hard"
        elif attempts_count >= self.failure_threshold_soft:
            reasons.append(f"已失败 {attempts_count} 次（软阈值 {self.failure_threshold_soft}）")
            if urgency != "hard":
                urgency = "soft"
        
        # 2. 检查时间消耗
        if elapsed_time >= self.time_threshold_hard:
            reasons.append(f"已耗时 {elapsed_time/60:.1f} 分钟（硬阈值 {self.time_threshold_hard/60:.1f} 分钟）")
            urgency = "hard"
        elif elapsed_time >= self.time_threshold_soft:
            reasons.append(f"已耗时 {elapsed_time/60:.1f} 分钟（软阈值 {self.time_threshold_soft/60:.1f} 分钟）")
            if urgency != "hard":
                urgency = "soft"
        
        # 3. 检查置信度
        if current_confidence is not None and current_confidence < self.confidence_threshold:
            reasons.append(f"当前置信度 {current_confidence:.1f}% < {self.confidence_threshold}%")
            if urgency != "hard":
                urgency = "soft"
        
        # 4. 检查重复方法
        if recent_methods and len(recent_methods) >= self.repeat_method_threshold:
            # 检查是否有重复方法
            method_counts = {}
            for method in recent_methods[-self.repeat_method_threshold:]:
                method_counts[method] = method_counts.get(method, 0) + 1
            
            max_repeat = max(method_counts.values()) if method_counts else 0
            if max_repeat >= self.repeat_method_threshold:
                reasons.append(f"同一方法重复失败 {max_repeat} 次")
                if urgency != "hard":
                    urgency = "soft"
        
        # 生成建议消息
        should_suggest = urgency != "none"
        message = ""
        
        if should_suggest:
            if urgency == "hard":
                message = (
                    f"⚠️ **强烈建议使用提示**：\n"
                    f"  - 原因：{'; '.join(reasons)}\n"
                    f"  - 建议：立即调用 `view_challenge_hint` 获取提示\n"
                    f"  - 提醒：使用提示会扣分，但可以避免浪费更多时间"
                )
            else:  # soft
                message = (
                    f"💡 **可以考虑使用提示**：\n"
                    f"  - 原因：{'; '.join(reasons)}\n"
                    f"  - 建议：如果下一次尝试仍失败，考虑调用 `view_challenge_hint`\n"
                    f"  - 提醒：使用提示会扣分"
                )
        
        return {
            "should_suggest": should_suggest,
            "urgency": urgency,
            "reasons": reasons,
            "message": message
        }
    
    def format_hint_guidance(
        self,
        challenge_code: str,
        attempts_count: int,
        elapsed_time: float,
        current_confidence: Optional[float] = None,
        recent_methods: Optional[list] = None
    ) -> str:
        """
        格式化提示引导消息（用于注入到 User Prompt）
        
        Returns:
            格式化的提示建议文本
        """
        suggestion = self.should_suggest_hint(
            attempts_count=attempts_count,
            elapsed_time=elapsed_time,
            current_confidence=current_confidence,
            recent_methods=recent_methods
        )
        
        if not suggestion["should_suggest"]:
            return ""
        
        return f"""
## 提示建议

{suggestion['message']}

**当前状态**：
- 题目代码: {challenge_code}
- 尝试次数: {attempts_count}
- 已耗时: {elapsed_time/60:.1f} 分钟
- 置信度: {current_confidence:.1f}% if current_confidence is not None else "未知"

**使用方法**：
```
调用工具: view_challenge_hint
参数: {{"challenge_code": "{challenge_code}"}}
```
"""


# 全局默认策略实例
default_hint_strategy = HintStrategy()


def get_hint_suggestion(
    challenge_code: str,
    attempts_count: int,
    start_time: datetime,
    current_confidence: Optional[float] = None,
    recent_methods: Optional[list] = None
) -> str:
    """
    获取提示建议（便捷函数）
    
    Args:
        challenge_code: 题目代码
        attempts_count: 尝试次数
        start_time: 开始时间
        current_confidence: 当前置信度
        recent_methods: 最近使用的方法
    
    Returns:
        提示建议文本（如果不建议则返回空字符串）
    """
    elapsed_time = (datetime.now() - start_time).total_seconds()
    
    return default_hint_strategy.format_hint_guidance(
        challenge_code=challenge_code,
        attempts_count=attempts_count,
        elapsed_time=elapsed_time,
        current_confidence=current_confidence,
        recent_methods=recent_methods
    )


# 示例用法
if __name__ == "__main__":
    # 创建策略
    strategy = HintStrategy(
        failure_threshold_soft=5,
        failure_threshold_hard=10,
        time_threshold_soft=300.0,
        time_threshold_hard=600.0
    )
    
    # 测试场景 1：失败 3 次（不建议）
    result = strategy.should_suggest_hint(
        attempts_count=3,
        elapsed_time=120.0,
        current_confidence=60.0
    )
    print("场景 1 - 失败 3 次:")
    print(f"  建议: {result['should_suggest']}")
    print(f"  紧急程度: {result['urgency']}")
    print()
    
    # 测试场景 2：失败 6 次（软建议）
    result = strategy.should_suggest_hint(
        attempts_count=6,
        elapsed_time=200.0,
        current_confidence=45.0
    )
    print("场景 2 - 失败 6 次:")
    print(f"  建议: {result['should_suggest']}")
    print(f"  紧急程度: {result['urgency']}")
    print(f"  消息: {result['message']}")
    print()
    
    # 测试场景 3：失败 12 次（硬建议）
    result = strategy.should_suggest_hint(
        attempts_count=12,
        elapsed_time=700.0,
        current_confidence=25.0,
        recent_methods=["sqli", "sqli", "sqli", "xss"]
    )
    print("场景 3 - 失败 12 次:")
    print(f"  建议: {result['should_suggest']}")
    print(f"  紧急程度: {result['urgency']}")
    print(f"  消息:\n{result['message']}")
