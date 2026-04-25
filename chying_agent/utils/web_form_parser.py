"""
Web 表单解析工具
================

提供 HTML 表单字段提取功能（纯函数工具）。
"""

from typing import Dict, Any
from collections import OrderedDict

from chying_agent.common import log_system_event


def extract_web_form_fields(html: str, form_index: int = 0) -> Dict[str, Any]:
    """
    智能提取 HTML 表单字段

    **关键功能**:
    - 提取所有表单字段（input, select, textarea）
    - 自动识别 hidden 字段
    - 保留字段顺序
    - 排除 disabled 字段
    - 支持多表单页面

    Args:
        html: HTML 响应内容
        form_index: 表单索引（默认 0，选择第一个表单）

    Returns:
        {
            "action": "/login",
            "method": "POST",
            "fields": {
                "username": {"value": "test", "type": "text", "hidden": True, "required": False},
                "user_id": {"value": "10032", "type": "text", "hidden": True, "required": False},
                "password": {"value": "", "type": "password", "hidden": False, "required": True}
            },
            "field_order": ["username", "user_id", "password"],
            "error": None  # 如果出错会包含错误信息
        }
    """
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')

        if not forms:
            log_system_event(
                "[Web工具] 未找到表单",
                {"html_length": len(html)}
            )
            return {
                "error": "未找到表单",
                "action": "",
                "method": "GET",
                "fields": {},
                "field_order": []
            }

        if form_index >= len(forms):
            log_system_event(
                f"[Web工具] 表单索引 {form_index} 超出范围，使用第一个表单",
                {"total_forms": len(forms)}
            )
            form_index = 0

        form = forms[form_index]

        result: Dict[str, Any] = {
            'action': form.get('action', ''),
            'method': form.get('method', 'GET').upper(),
            'fields': OrderedDict(),
            'field_order': [],
            'error': None
        }

        # 1. 提取所有 input 字段
        for input_tag in form.find_all('input'):
            name = input_tag.get('name')
            if not name:
                continue

            # 跳过 disabled 字段（不应提交）
            if 'disabled' in input_tag.attrs:
                continue

            field_type = input_tag.get('type', 'text').lower()

            # 跳过 submit/button/reset 类型
            if field_type in ['submit', 'button', 'reset', 'image']:
                continue

            result['fields'][name] = {
                'value': input_tag.get('value', ''),
                'type': field_type,
                'hidden': field_type == 'hidden' or 'hidden' in input_tag.attrs,
                'required': 'required' in input_tag.attrs,
                'readonly': 'readonly' in input_tag.attrs
            }
            result['field_order'].append(name)

        # 2. 提取 select 字段（下拉框）
        for select_tag in form.find_all('select'):
            name = select_tag.get('name')
            if not name or 'disabled' in select_tag.attrs:
                continue

            # 获取默认选中的 option
            selected = select_tag.find('option', selected=True)
            default_value = selected.get('value', '') if selected else ''

            result['fields'][name] = {
                'value': default_value,
                'type': 'select',
                'hidden': False,
                'required': 'required' in select_tag.attrs,
                'readonly': False
            }
            result['field_order'].append(name)

        # 3. 提取 textarea 字段
        for textarea_tag in form.find_all('textarea'):
            name = textarea_tag.get('name')
            if not name or 'disabled' in textarea_tag.attrs:
                continue

            result['fields'][name] = {
                'value': textarea_tag.get_text(strip=True),
                'type': 'textarea',
                'hidden': False,
                'required': 'required' in textarea_tag.attrs,
                'readonly': 'readonly' in textarea_tag.attrs
            }
            result['field_order'].append(name)

        # 统计 hidden 字段数量
        hidden_fields = [k for k, v in result['fields'].items() if v['hidden']]

        log_system_event(
            "[Web工具] ✅ 成功提取表单字段",
            {
                "total_fields": len(result['fields']),
                "hidden_fields": len(hidden_fields),
                "hidden_field_names": hidden_fields,
                "action": result['action'],
                "method": result['method']
            }
        )

        return result

    except ImportError:
        error_msg = "BeautifulSoup 未安装，请运行: pip install beautifulsoup4"
        log_system_event(
            f"[Web工具] ❌ {error_msg}",
            level="ERROR"
        )
        return {
            "error": error_msg,
            "action": "",
            "method": "GET",
            "fields": {},
            "field_order": []
        }
    except Exception as e:
        error_msg = f"表单解析失败: {str(e)}"
        log_system_event(
            f"[Web工具] ❌ {error_msg}",
            {"exception": str(e)},
            level="ERROR"
        )
        return {
            "error": error_msg,
            "action": "",
            "method": "GET",
            "fields": {},
            "field_order": []
        }


__all__ = ["extract_web_form_fields"]
