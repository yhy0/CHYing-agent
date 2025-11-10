"""
记忆工具定义
============

提供结构化的记忆记录工具，用于记录漏洞发现、成功利用和失败尝试。
"""
from typing import Optional, List, Dict
from datetime import datetime
from langchain_core.tools import tool

from sentinel_agent.common import log_security_event, log_system_event


# 运行时缓存（用于单次运行内的快速访问）
_runtime_cache = {
    "discoveries": [],  # 按时间排序的发现列表
    "attack_paths": [],  # 成功的攻击路径
    "failed_attempts": []  # 失败的尝试，用于避免重复
}


@tool
def record_vulnerability_discovery(
    target_ip: str, 
    port: int, 
    service: str, 
    vuln_type: str, 
    confidence: float, 
    description: str, 
    cve_id: Optional[str] = None
) -> str:
    """
    记录发现的漏洞信息到长期记忆中。
    
    Args:
        target_ip: 目标IP地址
        port: 端口号
        service: 服务名称和版本
        vuln_type: 漏洞类型（如 SQL注入、RCE、信息泄露等）
        confidence: 置信度 (0.0-1.0)
        description: 漏洞描述
        cve_id: CVE编号（如果有）
    
    Returns:
        记录确认信息
    """
    discovery = {
        "type": "vulnerability",
        "target_ip": target_ip,
        "port": port,
        "service": service,
        "vuln_type": vuln_type,
        "confidence": confidence,
        "description": description,
        "cve_id": cve_id,
        "timestamp": datetime.now().isoformat()
    }
    
    # 添加到运行时缓存
    _runtime_cache["discoveries"].append(discovery)
    
    log_security_event(
        f"[记忆] 记录漏洞发现: {vuln_type} on {target_ip}:{port}", 
        discovery
    )
    
    return f"Recorded vulnerability discovery: {vuln_type} on {target_ip}:{port} (confidence: {confidence})"


@tool  
def record_successful_exploit(
    target_ip: str, 
    port: int, 
    exploit_method: str, 
    payload: str, 
    result: str, 
    flag: Optional[str] = None
) -> str:
    """
    记录成功的利用尝试到长期记忆中，用于后续类似目标的参考。
    
    Args:
        target_ip: 目标IP地址
        port: 端口号
        exploit_method: 利用方法
        payload: 使用的载荷
        result: 利用结果
        flag: 获得的flag（如果有）
    
    Returns:
        记录确认信息
    """
    attack_path = {
        "type": "successful_exploit",
        "target_ip": target_ip,
        "port": port,
        "exploit_method": exploit_method,
        "payload": payload,
        "result": result,
        "flag": flag,
        "timestamp": datetime.now().isoformat()
    }
    
    # 添加到运行时缓存
    _runtime_cache["attack_paths"].append(attack_path)
    
    log_security_event(
        f"[记忆] 记录成功利用: {exploit_method} on {target_ip}:{port}", 
        attack_path
    )
    
    return f"Recorded successful exploit: {exploit_method} on {target_ip}:{port}"


@tool
def record_failed_attempt(
    target_ip: str, 
    port: int, 
    attempt_type: str, 
    reason: str, 
    details: str
) -> str:
    """
    记录失败的尝试，避免重复相同的错误。
    
    Args:
        target_ip: 目标IP地址
        port: 端口号
        attempt_type: 尝试类型
        reason: 失败原因
        details: 详细信息
    
    Returns:
        记录确认信息
    """
    failed_attempt = {
        "type": "failed_attempt",
        "target_ip": target_ip,
        "port": port,
        "attempt_type": attempt_type,
        "reason": reason,
        "details": details,
        "timestamp": datetime.now().isoformat()
    }
    
    # 添加到运行时缓存
    _runtime_cache["failed_attempts"].append(failed_attempt)
    
    log_security_event(
        f"[记忆] 记录失败尝试: {attempt_type} on {target_ip}:{port}", 
        failed_attempt
    )
    
    return f"Recorded failed attempt: {attempt_type} on {target_ip}:{port}"


@tool
def query_historical_knowledge(
    query: str, 
    target_ip: Optional[str] = None, 
    service_type: Optional[str] = None
) -> List[Dict]:
    """
    查询历史知识库，寻找相关的漏洞、利用方法或失败经验。
    
    Args:
        query: 查询字符串（如漏洞类型、服务名称等）
        target_ip: 目标IP（可选，用于查找针对特定目标的历史记录）
        service_type: 服务类型（可选，用于查找针对特定服务的历史记录）
    
    Returns:
        匹配的历史记录列表
    """
    if not query or not query.strip():
        log_system_event("[记忆] 查询字符串为空")
        return []
    
    results = []
    query_lower = query.lower()
    
    # 查询运行时缓存
    # 1. 查询漏洞发现
    for discovery in _runtime_cache["discoveries"]:
        if (query_lower in discovery.get("description", "").lower() or 
            query_lower in discovery.get("vuln_type", "").lower() or
            query_lower in discovery.get("service", "").lower()):
            if target_ip is None or discovery.get("target_ip") == target_ip:
                if service_type is None or service_type.lower() in discovery.get("service", "").lower():
                    results.append({
                        "source": "runtime_discovery",
                        **discovery
                    })
    
    # 2. 查询成功的攻击路径
    for attack_path in _runtime_cache["attack_paths"]:
        if (query_lower in attack_path.get("exploit_method", "").lower() or
            query_lower in attack_path.get("result", "").lower()):
            if target_ip is None or attack_path.get("target_ip") == target_ip:
                results.append({
                    "source": "runtime_attack_path",
                    **attack_path
                })
    
    # 3. 查询失败尝试
    for failed_attempt in _runtime_cache["failed_attempts"]:
        if (query_lower in failed_attempt.get("attempt_type", "").lower() or
            query_lower in failed_attempt.get("reason", "").lower()):
            if target_ip is None or failed_attempt.get("target_ip") == target_ip:
                results.append({
                    "source": "runtime_failed_attempt",
                    **failed_attempt
                })
    
    log_system_event(f"[记忆] 查询 '{query}' 返回 {len(results)} 条结果")
    
    return results


# ==================== 缓存管理函数 ====================

def get_all_discoveries() -> List[Dict]:
    """获取所有发现（用于报告生成）"""
    return _runtime_cache["discoveries"]


def get_all_attack_paths() -> List[Dict]:
    """获取所有成功的攻击路径"""
    return _runtime_cache["attack_paths"]


def get_all_failed_attempts() -> List[Dict]:
    """获取所有失败尝试"""
    return _runtime_cache["failed_attempts"]


def clear_runtime_memory():
    """清空运行时记忆（用于新的分析会话）"""
    _runtime_cache["discoveries"].clear()
    _runtime_cache["attack_paths"].clear()
    _runtime_cache["failed_attempts"].clear()
    log_system_event("[记忆] 已清空运行时缓存")


def get_memory_stats() -> Dict:
    """获取记忆系统统计信息"""
    return {
        "runtime_discoveries_count": len(_runtime_cache["discoveries"]),
        "runtime_attack_paths_count": len(_runtime_cache["attack_paths"]),
        "runtime_failed_attempts_count": len(_runtime_cache["failed_attempts"])
    }


# 导出所有记忆工具
MEMORY_TOOLS = [
    record_vulnerability_discovery,
    record_successful_exploit,
    record_failed_attempt,
    query_historical_knowledge
]


def get_memory_tools() -> List:
    """获取所有记忆工具"""
    return MEMORY_TOOLS
