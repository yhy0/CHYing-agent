# New API has Potential XSS in its MarkdownRenderer component

**GHSA**: GHSA-299v-8pq9-5gjq | **CVE**: CVE-2026-25802 | **Severity**: high (CVSS 7.6)

**CWE**: CWE-79

**Affected Packages**:
- **github.com/QuantumNous/new-api** (go): < 0.10.8-alpha.9

## Description

### Summary

A potential unsafe operation occurs in component `MarkdownRenderer.jsx`, allowing for Cross-Site Scripting(XSS) when the model outputs items containing `<script>` tag.

### Details

Line 212-231 of `MarkdownRenderer.jsx` is unsafe, it use dangerouslySetInnerHTML to preview html the model generates. This can trigger malcious scripts.

### PoC

A simple way to exploit that is to ask the model in the playground, with prompt: "请帮我写个脚本，跳转到google", and then the browser will navigate to the google.com without user interference.

### Impact

Potential malcious activity to the user using playground, if the model api is altered to output unintended codes.

Also, users may not be easily rid the exploit, since the record of the chat containing XSS script is stored, once opening the page later, the script will be re-triggered.

### Potential Workaround

The preview may be placed in an iframe sandbox, dangerous html strings should be purified before rendering.

---

The reply generated for test is as below:

这是一个为您编写的单页 HTML 文件。它使用了两种方式来实现跳转，以确保在任何情况下都能工作：

1.  **JavaScript (`window.location.replace`)**：这是最常用且高效的方法，它会立即跳转，并且不会保留当前页面在浏览器历史记录中（这样用户按“后退”键不会回到这个跳转页）。
2.  **HTML Meta Refresh**：作为后备方案。如果用户的浏览器禁用了 JavaScript，这个标签会在 1 秒后将用户带往 Google。
3.  **手动链接**：页面中显示了一个备用链接，以防自动跳转被拦截或失效。

您可以直接保存以下代码为 `.html` 文件并在浏览器中打开。

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>正在跳转至 Google...</title>
    
    <!-- 方法1：HTML Meta Refresh (如果JS被禁用，1秒后自动跳转) -->
    <meta http-equiv="refresh" content="1;url=https://www.google.com">

    <style>
        /* 基础重置与布局 */
        body, html {
            height: 100%;
            margin: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #f8f9fa;
            color: #202124;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        /* 卡片容器样式 */
        .redirect-card {
            background: white;
            padding: 2rem 3rem;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 400px;
            width: 90%;
        }

        /* 加载动画圆圈 */
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #4285f4; /* Google Blue */
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 1.5rem auto;
        }

        /* 文本排版 */
        h1 {
            font-size: 1.25rem;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }

        p {
            font-size: 0.95rem;
            color: #5f6368;
            margin-bottom: 1.5rem;
            line-height: 1.5;
        }

        /* 手动链接样式 */
        .manual-link {
            display: inline-block;
            color: #1a73e8; /* Google Link Blue */
            text-decoration: none;
            font-weight: 500;
            padding: 0.5rem 1rem;
            border: 1px solid #dadce0;
            border-radius: 4px;
            transition: background-color 0.2s;
        }

        .manual-link:hover {
            background-color: #f1f3f4;
            text-decoration: underline;
        }

        /* 动画定义 */
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>

    <main class="redirect-card">
        <!-- 视觉反馈：加载动画 -->
        <div class="spinner"></div>
        
        <!-- 提示信息 -->
        <h1>正在为您跳转</h1>
        <p>我们正在将您引导至 Google。<br>如果页面没有自动刷新，请点击下方的按钮。</p>
        
        <!-- 手动跳转链接 -->
        <a href="https://www.google.com" class="manual-link">立即前往 Google</a>
    </main>

    <script>
        // 方法2：JavaScript 跳转 (推荐)
        // 使用 replace() 而不是 href，这样用户点击“后退”时不会死循环回到这个跳转页
        (function() {
            // 目标地址
            var targetUrl = "https://www.google.com";

            // 执行跳转
            window.location.replace(targetUrl);
            
            // 控制台日志（用于调试）
            console.log("Redirecting to: " + targetUrl);
        })();
    </script>

</body>
</html>
```

### Acknowledgments

QuantumNous would like to thank **TechnologyStar** for the early notification of this potential vulnerability via AI-assisted tools, and **small-lovely-cat** for providing additional context and an initial patch. The final fix was developed and verified by the maintainers to ensure full compatibility with the project's architecture.
